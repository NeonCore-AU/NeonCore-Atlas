package dev.neoncore.atlas

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AtlasApp() }
    }
}

@Composable
private fun AtlasApp() {
    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            DashboardScreen()
        }
    }
}

@Composable
private fun DashboardScreen() {
    val connectDescription = stringResource(R.string.accessibility_connect_button)

    Column(modifier = Modifier.padding(24.dp)) {
        Text(text = stringResource(R.string.app_name), style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.connection_status_disconnected))
        Button(
            modifier = Modifier.semantics {
                contentDescription = connectDescription
            },
            onClick = {}
        ) {
            Text(text = stringResource(R.string.connection_action_connect))
        }
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.nodes_empty_title), style = MaterialTheme.typography.titleMedium)
        Text(text = stringResource(R.string.nodes_empty_description))
        OutlinedTextField(
            value = "",
            onValueChange = {},
            label = { Text(text = stringResource(R.string.subscription_import_url_placeholder)) }
        )
        Text(text = stringResource(R.string.nav_profiles))
        Text(text = stringResource(R.string.nav_routing))
        Text(text = stringResource(R.string.nav_logs))
        Text(text = stringResource(R.string.nav_settings))
    }
}
