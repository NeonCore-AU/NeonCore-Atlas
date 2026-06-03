struct AuthChainCodec {
    key: Vec<u8>,
    iv: Vec<u8>,
    user: SsrUserData,
    auth: SsrAuthData,
    profile: AuthChainProfile,
    data_size_list: Vec<usize>,
    data_size_list2: Vec<usize>,
    sent_header: bool,
    pack_id: u32,
    recv_id: u32,
    last_client_hash: Vec<u8>,
    last_server_hash: Vec<u8>,
    enc_rc4: Option<Rc4>,
    dec_rc4: Option<Rc4>,
    random_client: XorShift128Plus,
    random_server: XorShift128Plus,
    recv_buffer: BytesMut,
    raw_recv: bool,
}

#[derive(Clone, Copy)]
struct AuthChainProfile {
    salt: &'static str,
    variant: AuthChainVariant,
}

impl AuthChainProfile {
    const fn new(salt: &'static str, variant: AuthChainVariant) -> Self {
        Self { salt, variant }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthChainVariant {
    A,
    B,
    C,
    D,
    E,
    F,
}

impl AuthChainCodec {
    fn new(
        key: Vec<u8>,
        iv: Vec<u8>,
        protocol_param: String,
        profile: AuthChainProfile,
    ) -> Self {
        let user = SsrUserData::auth_chain(&key, &protocol_param);
        let key_change_interval = auth_chain_f_interval(&protocol_param);
        let mut codec = Self {
            key,
            iv,
            user,
            auth: SsrAuthData::new(),
            profile,
            data_size_list: Vec::new(),
            data_size_list2: Vec::new(),
            sent_header: false,
            pack_id: 1,
            recv_id: 1,
            last_client_hash: Vec::new(),
            last_server_hash: Vec::new(),
            enc_rc4: None,
            dec_rc4: None,
            random_client: XorShift128Plus::default(),
            random_server: XorShift128Plus::default(),
            recv_buffer: BytesMut::new(),
            raw_recv: false,
        };
        let data_size_key = codec.key.clone();
        match codec.profile.variant {
            AuthChainVariant::A => {}
            AuthChainVariant::B => codec.init_data_size_b(),
            AuthChainVariant::C => codec.init_data_size_c(false, &data_size_key),
            AuthChainVariant::D | AuthChainVariant::E => {
                codec.init_data_size_c(true, &data_size_key)
            }
            AuthChainVariant::F => {
                let key = auth_chain_f_data_size_key(
                    &data_size_key,
                    key_change_interval,
                    codec.auth.timestamp,
                );
                codec.init_data_size_c(true, &key);
            }
        }
        codec
    }

    fn encode(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(payload.len() + 96);
        let mut remaining = payload;
        if !self.sent_header {
            let data_len = get_auth_sha1_v4_data_len(remaining);
            self.pack_auth_data(&mut output, &remaining[..data_len])?;
            remaining = &remaining[data_len..];
            self.sent_header = true;
        }
        while remaining.len() > 2800 {
            self.pack_data(&mut output, &remaining[..2800])?;
            remaining = &remaining[2800..];
        }
        if !remaining.is_empty() {
            self.pack_data(&mut output, remaining)?;
        }
        Ok(output)
    }

    fn decode(&mut self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        if self.raw_recv {
            output.extend_from_slice(payload);
            return Ok(());
        }
        self.recv_buffer.extend_from_slice(payload);
        while self.recv_buffer.len() > 4 {
            if self.last_server_hash.len() < 16 || self.dec_rc4.is_none() {
                break;
            }
            let encoded_len = u16::from_le_bytes([self.recv_buffer[0], self.recv_buffer[1]]);
            let hash_len =
                u16::from_le_bytes([self.last_server_hash[14], self.last_server_hash[15]]);
            let data_len = (encoded_len ^ hash_len) as usize;
            let last_server_hash = self.last_server_hash.clone();
            let rand_len = self.rand_len(data_len, &last_server_hash, false);
            let length = data_len + rand_len;
            if length >= 4096 {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_chain response length is invalid",
                ));
            }
            if 4 + length > self.recv_buffer.len() {
                break;
            }
            let server_hash = with_appended_u32_le(&self.user.user_key, self.recv_id, |mac_key| {
                hmac_md5(mac_key, &self.recv_buffer[..length + 2])
            });
            if server_hash[..2] != self.recv_buffer[length + 2..length + 4] {
                self.raw_recv = true;
                self.recv_buffer.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_chain response checksum mismatch",
                ));
            }
            self.last_server_hash = server_hash.to_vec();
            let mut pos = 2;
            if data_len > 0 && rand_len > 0 {
                pos += rand_start_pos(rand_len, &mut self.random_server);
            }
            let end = pos + data_len;
            if end > length + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ShadowsocksR auth_chain response padding is invalid",
                ));
            }
            let mut data = crate::buffer_pool::PooledBuffer::with_capacity(data_len);
            data.extend_from_slice(&self.recv_buffer[pos..end]);
            if let Some(dec) = &mut self.dec_rc4 {
                dec.apply_keystream(data.as_mut_slice());
            }
            if self.recv_id == 1 && data.len() >= 2 {
                output.extend_from_slice(&data[2..]);
            } else {
                output.extend_from_slice(&data);
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            let _ = self.recv_buffer.split_to(length + 4);
        }
        Ok(())
    }

    fn encode_packet(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut auth_data = [0_u8; 3];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut auth_data);
        let md5_data = hmac_md5(&self.key, &auth_data);
        let rand_len = self.udp_rand_len(&md5_data, true);
        let mut encrypted = crate::buffer_pool::PooledBuffer::with_capacity(payload.len());
        encrypted.extend_from_slice(payload);
        let rc4_key = ssr_chain_udp_rc4_key(&self.user.user_key, &md5_data);
        let mut rc4 = Rc4::new_from_slice(&rc4_key).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ShadowsocksR auth_chain UDP RC4 key",
            )
        })?;
        rc4.apply_keystream(encrypted.as_mut_slice());

        let mut output = Vec::with_capacity(encrypted.len() + rand_len + 8);
        output.extend_from_slice(&encrypted);
        push_random_bytes(&mut output, rand_len);
        output.extend_from_slice(&auth_data);
        let uid = u32::from_le_bytes(self.user.user_id)
            ^ u32::from_le_bytes(md5_data[..4].try_into().unwrap());
        output.extend_from_slice(&uid.to_le_bytes());
        let mac = hmac_md5(&self.user.user_key, &output);
        output.push(mac[0]);
        Ok(output)
    }

    fn decode_packet(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() < 9 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowsocksR auth_chain UDP packet is too short",
            ));
        }
        let mac_pos = payload.len() - 1;
        let mac = hmac_md5(&self.user.user_key, &payload[..mac_pos]);
        if mac[0] != payload[mac_pos] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowsocksR auth_chain UDP checksum mismatch",
            ));
        }
        let auth_start = payload.len() - 8;
        let md5_data = hmac_md5(&self.key, &payload[auth_start..mac_pos]);
        let rand_len = self.udp_rand_len(&md5_data, false);
        let data_end = auth_start.checked_sub(rand_len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowsocksR auth_chain UDP padding is invalid",
            )
        })?;
        let mut body = crate::buffer_pool::PooledBuffer::with_capacity(data_end);
        body.extend_from_slice(&payload[..data_end]);
        let rc4_key = ssr_chain_udp_rc4_key(&self.user.user_key, &md5_data);
        let mut rc4 = Rc4::new_from_slice(&rc4_key).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ShadowsocksR auth_chain UDP RC4 key",
            )
        })?;
        rc4.apply_keystream(body.as_mut_slice());
        Ok(body.into_vec())
    }

    fn pack_auth_data(&mut self, output: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        let mut mac_key =
            crate::buffer_pool::PooledBuffer::with_capacity(self.iv.len() + self.key.len());
        mac_key.extend_from_slice(&self.iv);
        mac_key.extend_from_slice(&self.key);
        let start = output.len();
        push_random_bytes(output, 4);
        self.last_client_hash = hmac_md5(mac_key.as_slice(), &output[start..]).to_vec();
        self.init_rc4()?;
        output.extend_from_slice(&self.last_client_hash[..8]);
        let uid = u32::from_le_bytes(self.user.user_id)
            ^ u32::from_le_bytes(self.last_client_hash[8..12].try_into().unwrap());
        output.extend_from_slice(&uid.to_le_bytes());
        output.extend_from_slice(
            &self
                .auth
                .encrypted_block(&self.user.user_key, 4, 0, self.profile.salt),
        );
        self.last_server_hash = hmac_md5(&self.user.user_key, &output[start + 12..]).to_vec();
        output.extend_from_slice(&self.last_server_hash[..4]);
        self.pack_data(output, data)
    }

    fn pack_data(&mut self, output: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        let mut encrypted = crate::buffer_pool::PooledBuffer::with_capacity(data.len());
        encrypted.extend_from_slice(data);
        if let Some(enc) = &mut self.enc_rc4 {
            enc.apply_keystream(encrypted.as_mut_slice());
        }
        let pack_id = self.pack_id;
        self.pack_id = self.pack_id.wrapping_add(1);
        let hash_len = u16::from_le_bytes([self.last_client_hash[14], self.last_client_hash[15]]);
        let encoded_len = (encrypted.len() as u16) ^ hash_len;
        let start = output.len();
        output.extend_from_slice(&encoded_len.to_le_bytes());
        self.put_mixed_rand_and_data(output, &encrypted);
        self.last_client_hash = with_appended_u32_le(&self.user.user_key, pack_id, |mac_key| {
            hmac_md5(mac_key, &output[start..]).to_vec()
        });
        output.extend_from_slice(&self.last_client_hash[..2]);
        Ok(())
    }

    fn put_mixed_rand_and_data(&mut self, output: &mut Vec<u8>, data: &[u8]) {
        let last_client_hash = self.last_client_hash.clone();
        let rand_len = self.rand_len(data.len(), &last_client_hash, true);
        if data.is_empty() {
            push_random_bytes(output, rand_len);
        } else if rand_len > 0 {
            let start = rand_start_pos(rand_len, &mut self.random_client);
            push_random_bytes(output, start);
            output.extend_from_slice(data);
            push_random_bytes(output, rand_len.saturating_sub(start));
        } else {
            output.extend_from_slice(data);
        }
    }

    fn init_rc4(&mut self) -> io::Result<()> {
        let key_material = format!(
            "{}{}",
            BASE64_STANDARD.encode(&self.user.user_key),
            BASE64_STANDARD.encode(&self.last_client_hash)
        );
        let key = shadowsocks_evp_bytes_to_key(key_material.as_bytes(), 16);
        self.enc_rc4 = Some(Rc4::new_from_slice(&key).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SSR auth_chain RC4 key",
            )
        })?);
        self.dec_rc4 = Some(Rc4::new_from_slice(&key).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SSR auth_chain RC4 key",
            )
        })?);
        Ok(())
    }

    fn rand_len(&mut self, len: usize, hash: &[u8], client: bool) -> usize {
        match self.profile.variant {
            AuthChainVariant::A => {
                let random = if client {
                    &mut self.random_client
                } else {
                    &mut self.random_server
                };
                rand_len_a(len, hash, random)
            }
            AuthChainVariant::B => self.rand_len_b(len, hash, client),
            AuthChainVariant::C => self.rand_len_c(len, hash, client),
            AuthChainVariant::D | AuthChainVariant::F => self.rand_len_d(len, hash, client),
            AuthChainVariant::E => self.rand_len_e(len, hash, client),
        }
    }

    fn rand_len_b(&mut self, len: usize, hash: &[u8], client: bool) -> usize {
        if len >= 1440 {
            return 0;
        }
        let random = if client {
            &mut self.random_client
        } else {
            &mut self.random_server
        };
        random.init_from_bin_and_length(hash, len);
        let overhead = 4;
        let pos = self
            .data_size_list
            .partition_point(|value| *value < len + overhead);
        if !self.data_size_list.is_empty() {
            let final_pos = pos + (random.next() as usize % self.data_size_list.len());
            if final_pos < self.data_size_list.len() {
                return self.data_size_list[final_pos].saturating_sub(len + overhead);
            }
        }
        let pos = self
            .data_size_list2
            .partition_point(|value| *value < len + overhead);
        if !self.data_size_list2.is_empty() {
            let final_pos = pos + (random.next() as usize % self.data_size_list2.len());
            if final_pos < self.data_size_list2.len() {
                return self.data_size_list2[final_pos].saturating_sub(len + overhead);
            }
            if final_pos < pos + self.data_size_list2.len().saturating_sub(1) {
                return 0;
            }
        }
        if len > 1300 {
            random.next() as usize % 31
        } else if len > 900 {
            random.next() as usize % 127
        } else if len > 400 {
            random.next() as usize % 521
        } else {
            random.next() as usize % 1021
        }
    }

    fn udp_rand_len(&mut self, hash: &[u8], client: bool) -> usize {
        let random = if client {
            &mut self.random_client
        } else {
            &mut self.random_server
        };
        random.init_from_bin(hash);
        (random.next() % 127) as usize
    }

    fn init_data_size_b(&mut self) {
        let mut random = XorShift128Plus::default();
        random.init_from_bin(&self.key);
        let mut length = random.next() % 8 + 4;
        while length > 0 {
            self.data_size_list
                .push((random.next() % 2340 % 2040 % 1440) as usize);
            length -= 1;
        }
        self.data_size_list.sort_unstable();
        let mut length = random.next() % 16 + 8;
        while length > 0 {
            self.data_size_list2
                .push((random.next() % 2340 % 2040 % 1440) as usize);
            length -= 1;
        }
        self.data_size_list2.sort_unstable();
    }

    fn init_data_size_c(&mut self, patch_high_water: bool, key: &[u8]) {
        self.data_size_list.clear();
        self.data_size_list2.clear();
        let mut random = XorShift128Plus::default();
        random.init_from_bin(key);
        let mut length = random.next() % 24 + 12;
        while length > 0 {
            self.data_size_list
                .push((random.next() % 2340 % 2040 % 1440) as usize);
            length -= 1;
        }
        self.data_size_list.sort_unstable();
        if patch_high_water {
            self.patch_data_size_high_water(&mut random);
        }
    }

    fn patch_data_size_high_water(&mut self, random: &mut XorShift128Plus) {
        while self
            .data_size_list
            .last()
            .copied()
            .unwrap_or_default()
            < 1300
            && self.data_size_list.len() < 64
        {
            self.data_size_list
                .push((random.next() % 2340 % 2040 % 1440) as usize);
            self.data_size_list.sort_unstable();
        }
    }

    fn rand_len_c(&mut self, len: usize, hash: &[u8], client: bool) -> usize {
        let other_size = len + 4;
        let random = if client {
            &mut self.random_client
        } else {
            &mut self.random_server
        };
        random.init_from_bin_and_length(hash, len);
        if other_size >= self.data_size_list.last().copied().unwrap_or_default() {
            return rand_len_after_initialized(len, random);
        }
        let pos = self
            .data_size_list
            .partition_point(|value| *value < other_size);
        if pos >= self.data_size_list.len() {
            return 0;
        }
        let span = self.data_size_list.len() - pos;
        let final_pos = pos + (random.next() as usize % span);
        self.data_size_list[final_pos].saturating_sub(other_size)
    }

    fn rand_len_d(&mut self, len: usize, hash: &[u8], client: bool) -> usize {
        let other_size = len + 4;
        if other_size >= self.data_size_list.last().copied().unwrap_or_default() {
            return 0;
        }
        let random = if client {
            &mut self.random_client
        } else {
            &mut self.random_server
        };
        random.init_from_bin_and_length(hash, len);
        let pos = self
            .data_size_list
            .partition_point(|value| *value < other_size);
        if pos >= self.data_size_list.len() {
            return 0;
        }
        let span = self.data_size_list.len() - pos;
        let final_pos = pos + (random.next() as usize % span);
        self.data_size_list[final_pos].saturating_sub(other_size)
    }

    fn rand_len_e(&mut self, len: usize, hash: &[u8], client: bool) -> usize {
        let random = if client {
            &mut self.random_client
        } else {
            &mut self.random_server
        };
        random.init_from_bin_and_length(hash, len);
        let other_size = len + 4;
        if other_size >= self.data_size_list.last().copied().unwrap_or_default() {
            return 0;
        }
        let pos = self
            .data_size_list
            .partition_point(|value| *value < other_size);
        self.data_size_list
            .get(pos)
            .copied()
            .unwrap_or(other_size)
            .saturating_sub(other_size)
    }
}

#[derive(Default)]
struct XorShift128Plus {
    state: [u64; 2],
}

impl XorShift128Plus {
    fn next(&mut self) -> u64 {
        let mut x = self.state[0];
        let y = self.state[1];
        self.state[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.state[1] = x;
        x.wrapping_add(y)
    }

    fn init_from_bin(&mut self, data: &[u8]) {
        let mut full = [0_u8; 16];
        let take = data.len().min(16);
        full[..take].copy_from_slice(&data[..take]);
        self.state[0] = u64::from_le_bytes(full[..8].try_into().unwrap());
        self.state[1] = u64::from_le_bytes(full[8..16].try_into().unwrap());
    }

    fn init_from_bin_and_length(&mut self, data: &[u8], len: usize) {
        let mut full = [0_u8; 16];
        let take = data.len().min(16);
        full[..take].copy_from_slice(&data[..take]);
        full[..2].copy_from_slice(&(len as u16).to_le_bytes());
        self.state[0] = u64::from_le_bytes(full[..8].try_into().unwrap());
        self.state[1] = u64::from_le_bytes(full[8..16].try_into().unwrap());
        for _ in 0..4 {
            self.next();
        }
    }
}

fn rand_len_a(len: usize, hash: &[u8], random: &mut XorShift128Plus) -> usize {
    if len > 1440 {
        return 0;
    }
    random.init_from_bin_and_length(hash, len);
    rand_len_after_initialized(len, random)
}

fn rand_len_after_initialized(len: usize, random: &mut XorShift128Plus) -> usize {
    if len > 1300 {
        random.next() as usize % 31
    } else if len > 900 {
        random.next() as usize % 127
    } else if len > 400 {
        random.next() as usize % 521
    } else {
        random.next() as usize % 1021
    }
}

fn auth_chain_f_interval(protocol_param: &str) -> u64 {
    protocol_param
        .split_once('#')
        .map(|(_, interval)| interval)
        .unwrap_or(protocol_param)
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(60 * 60 * 24)
}

fn auth_chain_f_data_size_key(key: &[u8], interval: u64, timestamp: u32) -> Vec<u8> {
    let mut out = key.to_vec();
    let time_key = (u64::from(timestamp)) / interval;
    let time_key = time_key.to_be_bytes();
    for (idx, value) in time_key.iter().copied().enumerate().take(out.len().min(8)) {
        out[idx] ^= value;
    }
    out
}

fn rand_start_pos(len: usize, random: &mut XorShift128Plus) -> usize {
    if len == 0 {
        0
    } else {
        (random.next() % 8_589_934_609) as usize % len
    }
}
