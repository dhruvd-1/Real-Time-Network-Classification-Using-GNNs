#include <WiFi.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>

// WiFi credentials - CHANGE THESE
const char* ssid = "Dhruv's Iphone";           // Your WiFi name
const char* password = "81780206";   // Your WiFi password

// Server details - CHANGE THIS IP
const char* server_ip = "172.20.10.3";    // Your computer's IP address
const int server_port = 8080;

WebSocketsClient webSocket;
int nodeId = 1;  // CHANGE THIS: Set to 1, 2, or 3 for different ESP32s

// Anomaly control variables
bool anomalyMode = false;
unsigned long anomalyStartTime = 0;
int currentAttackType = 0;
unsigned long lastAttackChange = 0;
bool manualTrigger = false;

// Built-in LED for status indication
#define LED_PIN 2

void setup() {
    Serial.begin(115200);
    
    // Setup LED
    pinMode(LED_PIN, OUTPUT);
    pinMode(0, INPUT_PULLUP);  // Built-in button for manual anomaly trigger
    
    // Startup LED sequence
    for(int i = 0; i < 3; i++) {
        digitalWrite(LED_PIN, HIGH);
        delay(200);
        digitalWrite(LED_PIN, LOW);
        delay(200);
    }
    
    Serial.println("🚀 ESP32 GNN-IDS Node Starting...");
    Serial.println("Node ID: " + String(nodeId));
    
    // Connect to WiFi
    Serial.println("Connecting to WiFi: " + String(ssid));
    WiFi.begin(ssid, password);
    
    int wifiAttempts = 0;
    while (WiFi.status() != WL_CONNECTED && wifiAttempts < 30) {
        delay(1000);
        Serial.print(".");
        wifiAttempts++;
        
        // Blink LED while connecting
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println();
        Serial.println("✅ WiFi connected!");
        Serial.print("📍 IP address: ");
        Serial.println(WiFi.localIP());
        Serial.print("📶 Signal strength: ");
        Serial.println(WiFi.RSSI());
        
        // WiFi connected - solid LED
        digitalWrite(LED_PIN, HIGH);
    } else {
        Serial.println("❌ WiFi connection failed!");
        // Rapid blink for WiFi failure
        while(true) {
            digitalWrite(LED_PIN, HIGH);
            delay(100);
            digitalWrite(LED_PIN, LOW);
            delay(100);
        }
    }
    
    // Connect to WebSocket server
    Serial.println("Connecting to server: " + String(server_ip) + ":" + String(server_port));
    webSocket.begin(server_ip, server_port, "/");
    webSocket.onEvent(webSocketEvent);
    webSocket.setReconnectInterval(5000);
    
    Serial.println("🛡️ GNN-IDS Node " + String(nodeId) + " Ready!");
    Serial.println("📊 Generating NSL-KDD compatible network data");
    Serial.println("🔴 Press BOOT button for manual anomaly trigger");
}

void loop() {
    webSocket.loop();
    
    // Check for manual anomaly trigger
    checkManualTrigger();
    
    // Manage anomaly mode timing
    manageAnomalyMode();
    
    // Send data every 3 seconds
    static unsigned long lastSend = 0;
    if (millis() - lastSend > 3000) {
        sendNetworkData();
        lastSend = millis();
    }
    
    // LED status indication
    updateLEDStatus();
}

void checkManualTrigger() {
    static unsigned long lastButtonPress = 0;
    
    if (digitalRead(0) == LOW && millis() - lastButtonPress > 1000) {
        manualTrigger = true;
        anomalyMode = true;
        anomalyStartTime = millis();
        currentAttackType = random(0, 5);
        lastAttackChange = millis();
        lastButtonPress = millis();
        
        Serial.println("🔴 MANUAL ANOMALY TRIGGERED!");
        Serial.println("Attack Type: " + String(currentAttackType));
        
        // Flash LED for manual trigger
        for(int i = 0; i < 5; i++) {
            digitalWrite(LED_PIN, LOW);
            delay(100);
            digitalWrite(LED_PIN, HIGH);
            delay(100);
        }
    }
}

void manageAnomalyMode() {
    // Auto-enter anomaly mode randomly (15% chance every 45 seconds)
    if (!anomalyMode && !manualTrigger && millis() - lastAttackChange > 45000) {
        if (random(0, 100) < 15) {
            anomalyMode = true;
            anomalyStartTime = millis();
            currentAttackType = random(0, 5);
            lastAttackChange = millis();
            
            Serial.println("🔴 AUTO ANOMALY MODE ACTIVATED");
            Serial.println("Attack Type: " + getAttackTypeName(currentAttackType));
        }
    }
    
    // Exit anomaly mode after 20-40 seconds
    if (anomalyMode && millis() - anomalyStartTime > random(20000, 40000)) {
        anomalyMode = false;
        manualTrigger = false;
        lastAttackChange = millis();
        Serial.println("🟢 ANOMALY MODE DEACTIVATED");
    }
}

void sendNetworkData() {
    DynamicJsonDocument doc(2048);
    doc["node_id"] = nodeId;
    doc["timestamp"] = millis();
    doc["wifi_rssi"] = WiFi.RSSI();
    doc["free_heap"] = ESP.getFreeHeap();
    
    if (anomalyMode) {
        generateAnomalousData(doc);
    } else {
        generateNormalData(doc);
    }
    
    String payload;
    serializeJson(doc, payload);
    webSocket.sendTXT(payload);
    
    // Brief LED flash for data transmission
    digitalWrite(LED_PIN, LOW);
    delay(50);
    digitalWrite(LED_PIN, HIGH);
}

void generateNormalData(DynamicJsonDocument& doc) {
    // Generate NSL-KDD compatible normal network data
    doc["duration"] = random(1, 300);
    doc["protocol_type"] = "tcp";
    doc["service"] = getRandomNormalService();
    doc["flag"] = "SF";
    doc["src_bytes"] = random(100, 10000);
    doc["dst_bytes"] = random(100, 10000);
    doc["land"] = 0;
    doc["wrong_fragment"] = 0;
    doc["urgent"] = 0;
    doc["hot"] = random(0, 3);
    doc["num_failed_logins"] = 0;
    doc["logged_in"] = 1;
    doc["num_compromised"] = 0;
    doc["root_shell"] = 0;
    doc["su_attempted"] = 0;
    doc["num_root"] = 0;
    doc["num_file_creations"] = random(0, 2);
    doc["num_shells"] = 0;
    doc["num_access_files"] = 0;
    doc["num_outbound_cmds"] = 0;
    doc["is_host_login"] = 0;
    doc["is_guest_login"] = 0;
    doc["count"] = random(1, 20);
    doc["srv_count"] = random(1, 20);
    doc["serror_rate"] = random(0, 5) / 100.0;
    doc["srv_serror_rate"] = random(0, 5) / 100.0;
    doc["rerror_rate"] = random(0, 5) / 100.0;
    doc["srv_rerror_rate"] = random(0, 5) / 100.0;
    doc["same_srv_rate"] = random(70, 100) / 100.0;
    doc["diff_srv_rate"] = random(0, 30) / 100.0;
    doc["srv_diff_host_rate"] = random(0, 20) / 100.0;
    doc["dst_host_count"] = random(1, 50);
    doc["dst_host_srv_count"] = random(1, 30);
    doc["dst_host_same_srv_rate"] = random(70, 100) / 100.0;
    doc["dst_host_diff_srv_rate"] = random(0, 30) / 100.0;
    doc["dst_host_same_src_port_rate"] = random(0, 50) / 100.0;
    doc["dst_host_srv_diff_host_rate"] = random(0, 20) / 100.0;
    doc["dst_host_serror_rate"] = random(0, 10) / 100.0;
    doc["dst_host_srv_serror_rate"] = random(0, 10) / 100.0;
    doc["dst_host_rerror_rate"] = random(0, 10) / 100.0;
    doc["dst_host_srv_rerror_rate"] = random(0, 10) / 100.0;
    
    doc["attack_type"] = "normal";
    doc["is_anomaly"] = false;
    
    Serial.println("🟢 Normal NSL-KDD data - Node " + String(nodeId));
}

void generateAnomalousData(DynamicJsonDocument& doc) {
    switch (currentAttackType) {
        case 0:
            generateDoSAttack(doc);
            break;
        case 1:
            generatePortScan(doc);
            break;
        case 2:
            generateR2LAttack(doc);
            break;
        case 3:
            generateU2RAttack(doc);
            break;
        case 4:
            generateProbeAttack(doc);
            break;
    }
    
    doc["is_anomaly"] = true;
    Serial.println("🔴 " + getAttackTypeName(currentAttackType) + " - Node " + String(nodeId));
}

void generateDoSAttack(DynamicJsonDocument& doc) {
    // Denial of Service attack pattern
    doc["duration"] = 0;
    doc["protocol_type"] = "tcp";
    doc["service"] = "http";
    doc["flag"] = "S0";  // SYN flood
    doc["src_bytes"] = random(0, 100);
    doc["dst_bytes"] = 0;
    doc["land"] = 0;
    doc["wrong_fragment"] = 0;
    doc["urgent"] = 0;
    doc["hot"] = 0;
    doc["num_failed_logins"] = 0;
    doc["logged_in"] = 0;
    doc["num_compromised"] = 0;
    doc["root_shell"] = 0;
    doc["su_attempted"] = 0;
    doc["num_root"] = 0;
    doc["num_file_creations"] = 0;
    doc["num_shells"] = 0;
    doc["num_access_files"] = 0;
    doc["num_outbound_cmds"] = 0;
    doc["is_host_login"] = 0;
    doc["is_guest_login"] = 0;
    doc["count"] = random(200, 1000);         // VERY HIGH
    doc["srv_count"] = random(200, 1000);     // VERY HIGH
    doc["serror_rate"] = random(80, 100) / 100.0;    // HIGH
    doc["srv_serror_rate"] = random(80, 100) / 100.0;
    doc["rerror_rate"] = random(0, 10) / 100.0;
    doc["srv_rerror_rate"] = random(0, 10) / 100.0;
    doc["same_srv_rate"] = random(90, 100) / 100.0;
    doc["diff_srv_rate"] = random(0, 10) / 100.0;
    doc["srv_diff_host_rate"] = random(0, 10) / 100.0;
    doc["dst_host_count"] = 1;
    doc["dst_host_srv_count"] = 1;
    doc["dst_host_same_srv_rate"] = random(90, 100) / 100.0;
    doc["dst_host_diff_srv_rate"] = random(0, 10) / 100.0;
    doc["dst_host_same_src_port_rate"] = random(0, 10) / 100.0;
    doc["dst_host_srv_diff_host_rate"] = random(0, 10) / 100.0;
    doc["dst_host_serror_rate"] = random(80, 100) / 100.0;
    doc["dst_host_srv_serror_rate"] = random(80, 100) / 100.0;
    doc["dst_host_rerror_rate"] = random(0, 10) / 100.0;
    doc["dst_host_srv_rerror_rate"] = random(0, 10) / 100.0;
    
    doc["attack_type"] = "dos";
}

void generatePortScan(DynamicJsonDocument& doc) {
    // Port scanning attack
    doc["duration"] = 0;
    doc["protocol_type"] = "tcp";
    doc["service"] = getRandomService();
    doc["flag"] = "REJ";  // Rejected connections
    doc["src_bytes"] = 0;
    doc["dst_bytes"] = 0;
    doc["land"] = 0;
    doc["wrong_fragment"] = 0;
    doc["urgent"] = 0;
    doc["hot"] = 0;
    doc["num_failed_logins"] = 0;
    doc["logged_in"] = 0;
    doc["num_compromised"] = 0;
    doc["root_shell"] = 0;
    doc["su_attempted"] = 0;
    doc["num_root"] = 0;
    doc["num_file_creations"] = 0;
    doc["num_shells"] = 0;
    doc["num_access_files"] = 0;
    doc["num_outbound_cmds"] = 0;
    doc["is_host_login"] = 0;
    doc["is_guest_login"] = 0;
    doc["count"] = random(50, 200);
    doc["srv_count"] = random(10, 50);
    doc["serror_rate"] = random(70, 100) / 100.0;
    doc["srv_serror_rate"] = random(70, 100) / 100.0;
    doc["rerror_rate"] = random(80, 100) / 100.0;    // HIGH rejection
    doc["srv_rerror_rate"] = random(80, 100) / 100.0;
    doc["same_srv_rate"] = random(0, 30) / 100.0;
    doc["diff_srv_rate"] = random(70, 100) / 100.0;  // Different services
    doc["srv_diff_host_rate"] = random(0, 30) / 100.0;
    doc["dst_host_count"] = random(100, 255);        // Many hosts
    doc["dst_host_srv_count"] = random(50, 200);
    doc["dst_host_same_srv_rate"] = random(0, 30) / 100.0;
    doc["dst_host_diff_srv_rate"] = random(70, 100) / 100.0;
    doc["dst_host_same_src_port_rate"] = random(0, 20) / 100.0;
    doc["dst_host_srv_diff_host_rate"] = random(70, 100) / 100.0;
    doc["dst_host_serror_rate"] = random(70, 100) / 100.0;
    doc["dst_host_srv_serror_rate"] = random(70, 100) / 100.0;
    doc["dst_host_rerror_rate"] = random(80, 100) / 100.0;
    doc["dst_host_srv_rerror_rate"] = random(80, 100) / 100.0;
    
    doc["attack_type"] = "portscan";
}

void generateR2LAttack(DynamicJsonDocument& doc) {
    // Remote to Local attack (brute force)
    doc["duration"] = random(1, 60);
    doc["protocol_type"] = "tcp";
    doc["service"] = "ftp";
    doc["flag"] = "SF";
    doc["src_bytes"] = random(100, 1000);
    doc["dst_bytes"] = random(100, 1000);
    doc["land"] = 0;
    doc["wrong_fragment"] = 0;
    doc["urgent"] = 0;
    doc["hot"] = random(5, 20);               // Hot indicators
    doc["num_failed_logins"] = random(5, 50); // MANY failed logins
    doc["logged_in"] = 0;                     // Failed login
    doc["num_compromised"] = 0;
    doc["root_shell"] = 0;
    doc["su_attempted"] = 0;
    doc["num_root"] = 0;
    doc["num_file_creations"] = 0;
    doc["num_shells"] = 0;
    doc["num_access_files"] = 0;
    doc["num_outbound_cmds"] = 0;
    doc["is_host_login"] = 0;
    doc["is_guest_login"] = 0;
    doc["count"] = random(20, 100);
    doc["srv_count"] = random(20, 100);
    doc["serror_rate"] = random(0, 20) / 100.0;
    doc["srv_serror_rate"] = random(0, 20) / 100.0;
    doc["rerror_rate"] = random(0, 20) / 100.0;
    doc["srv_rerror_rate"] = random(0, 20) / 100.0;
    doc["same_srv_rate"] = random(80, 100) / 100.0;
    doc["diff_srv_rate"] = random(0, 20) / 100.0;
    doc["srv_diff_host_rate"] = random(0, 20) / 100.0;
    doc["dst_host_count"] = random(1, 10);
    doc["dst_host_srv_count"] = random(1, 10);
    doc["dst_host_same_srv_rate"] = random(80, 100) / 100.0;
    doc["dst_host_diff_srv_rate"] = random(0, 20) / 100.0;
    doc["dst_host_same_src_port_rate"] = random(0, 30) / 100.0;
    doc["dst_host_srv_diff_host_rate"] = random(0, 20) / 100.0;
    doc["dst_host_serror_rate"] = random(0, 20) / 100.0;
    doc["dst_host_srv_serror_rate"] = random(0, 20) / 100.0;
    doc["dst_host_rerror_rate"] = random(0, 20) / 100.0;
    doc["dst_host_srv_rerror_rate"] = random(0, 20) / 100.0;
    
    doc["attack_type"] = "r2l";
}

void generateU2RAttack(DynamicJsonDocument& doc) {
    // User to Root attack
    doc["duration"] = random(60, 300);
    doc["protocol_type"] = "tcp";
    doc["service"] = "telnet";
    doc["flag"] = "SF";
    doc["src_bytes"] = random(1000, 5000);
    doc["dst_bytes"] = random(1000, 5000);
    doc["land"] = 0;
    doc["wrong_fragment"] = 0;
    doc["urgent"] = 0;
    doc["hot"] = random(10, 50);              // Many hot indicators
    doc["num_failed_logins"] = random(0, 3);
    doc["logged_in"] = 1;                     // Successfully logged in
    doc["num_compromised"] = random(1, 10);   // Compromise indicators
    doc["root_shell"] = 1;                    // ROOT ACCESS
    doc["su_attempted"] = random(1, 5);       // SU attempts
    doc["num_root"] = random(1, 20);          // Root operations
    doc["num_file_creations"] = random(5, 20); // File operations
    doc["num_shells"] = random(1, 5);         // Shell access
    doc["num_access_files"] = random(1, 10);  // Access files
    doc["num_outbound_cmds"] = 0;
    doc["is_host_login"] = 0;
    doc["is_guest_login"] = 0;
    doc["count"] = random(1, 20);
    doc["srv_count"] = random(1, 20);
    doc["serror_rate"] = random(0, 10) / 100.0;
    doc["srv_serror_rate"] = random(0, 10) / 100.0;
    doc["rerror_rate"] = random(0, 10) / 100.0;
    doc["srv_rerror_rate"] = random(0, 10) / 100.0;
    doc["same_srv_rate"] = random(60, 100) / 100.0;
    doc["diff_srv_rate"] = random(0, 40) / 100.0;
    doc["srv_diff_host_rate"] = random(0, 40) / 100.0;
    doc["dst_host_count"] = random(1, 10);
    doc["dst_host_srv_count"] = random(1, 10);
    doc["dst_host_same_srv_rate"] = random(60, 100) / 100.0;
    doc["dst_host_diff_srv_rate"] = random(0, 40) / 100.0;
    doc["dst_host_same_src_port_rate"] = random(0, 50) / 100.0;
    doc["dst_host_srv_diff_host_rate"] = random(0, 40) / 100.0;
    doc["dst_host_serror_rate"] = random(0, 10) / 100.0;
    doc["dst_host_srv_serror_rate"] = random(0, 10) / 100.0;
    doc["dst_host_rerror_rate"] = random(0, 10) / 100.0;
    doc["dst_host_srv_rerror_rate"] = random(0, 10) / 100.0;
    
    doc["attack_type"] = "u2r";
}

void generateProbeAttack(DynamicJsonDocument& doc) {
    // Network probe attack
    doc["duration"] = random(0, 10);
    doc["protocol_type"] = "icmp";
    doc["service"] = "ecr_i";
    doc["flag"] = "SF";
    doc["src_bytes"] = random(0, 500);
    doc["dst_bytes"] = random(0, 500);
    doc["land"] = 0;
    doc["wrong_fragment"] = 0;
    doc["urgent"] = 0;
    doc["hot"] = 0;
    doc["num_failed_logins"] = 0;
    doc["logged_in"] = 0;
    doc["num_compromised"] = 0;
    doc["root_shell"] = 0;
    doc["su_attempted"] = 0;
    doc["num_root"] = 0;
    doc["num_file_creations"] = 0;
    doc["num_shells"] = 0;
    doc["num_access_files"] = 0;
    doc["num_outbound_cmds"] = 0;
    doc["is_host_login"] = 0;
    doc["is_guest_login"] = 0;
    doc["count"] = random(100, 300);          // Many probes
    doc["srv_count"] = random(50, 200);
    doc["serror_rate"] = random(0, 30) / 100.0;
    doc["srv_serror_rate"] = random(0, 30) / 100.0;
    doc["rerror_rate"] = random(0, 30) / 100.0;
    doc["srv_rerror_rate"] = random(0, 30) / 100.0;
    doc["same_srv_rate"] = random(0, 50) / 100.0;
    doc["diff_srv_rate"] = random(50, 100) / 100.0; // Different services
    doc["srv_diff_host_rate"] = random(50, 100) / 100.0;
    doc["dst_host_count"] = random(50, 255);        // Many hosts
    doc["dst_host_srv_count"] = random(30, 150);
    doc["dst_host_same_srv_rate"] = random(0, 50) / 100.0;
    doc["dst_host_diff_srv_rate"] = random(50, 100) / 100.0;
    doc["dst_host_same_src_port_rate"] = random(0, 30) / 100.0;
    doc["dst_host_srv_diff_host_rate"] = random(50, 100) / 100.0;
    doc["dst_host_serror_rate"] = random(0, 30) / 100.0;
    doc["dst_host_srv_serror_rate"] = random(0, 30) / 100.0;
    doc["dst_host_rerror_rate"] = random(0, 30) / 100.0;
    doc["dst_host_srv_rerror_rate"] = random(0, 30) / 100.0;
    
    doc["attack_type"] = "probe";
}

String getRandomNormalService() {
    String services[] = {"http", "ftp", "telnet", "smtp", "pop3", "ssh", "dns"};
    return services[random(0, 7)];
}

String getRandomService() {
    String services[] = {"http", "ftp", "telnet", "smtp", "pop3", "ssh", "dns", 
                        "https", "imap", "snmp", "finger", "nntp", "whois"};
    return services[random(0, 13)];
}

String getAttackTypeName(int type) {
    switch(type) {
        case 0: return "DoS Attack";
        case 1: return "Port Scan";
        case 2: return "R2L Attack";
        case 3: return "U2R Attack";
        case 4: return "Probe Attack";
        default: return "Unknown";
    }
}

void updateLEDStatus() {
    static unsigned long lastLEDUpdate = 0;
    static bool ledState = true;
    
    if (millis() - lastLEDUpdate > 1000) {
        if (WiFi.status() != WL_CONNECTED) {
            // WiFi disconnected - fast blink
            digitalWrite(LED_PIN, !digitalRead(LED_PIN));
        } else if (anomalyMode) {
            // Anomaly mode - slow blink
            ledState = !ledState;
            digitalWrite(LED_PIN, ledState);
        } else {
            // Normal mode - solid on
            digitalWrite(LED_PIN, HIGH);
        }
        lastLEDUpdate = millis();
    }
}

void webSocketEvent(WStype_t type, uint8_t * payload, size_t length) {
    switch(type) {
        case WStype_DISCONNECTED:
            Serial.println("❌ Disconnected from server");
            break;
            
        case WStype_CONNECTED:
            Serial.printf("✅ Connected to server: %s\n", payload);
            // Send initial identification
            String initMsg = "{\"type\":\"init\",\"node_id\":" + String(nodeId) + "}";
            webSocket.sendTXT(initMsg);
            break;
            
        case WStype_TEXT:
            Serial.printf("📨 Server message: %s\n", payload);
            handleServerMessage(String((char*)payload));
            break;
            
        case WStype_ERROR:
            Serial.printf("❌ WebSocket error: %s\n", payload);
            break;
            
        case WStype_PING:
            Serial.println("📡 Ping from server");
            break;
            
        case WStype_PONG:
            Serial.println("📡 Pong from server");
            break;
    }
}

void handleServerMessage(String message) {
    DynamicJsonDocument doc(512);
    deserializeJson(doc, message);
    
    String msgType = doc["type"];
    
    if (msgType == "gnn_anomaly_alert") {
        float confidence = doc["confidence"];
        Serial.println("🚨 GNN ANOMALY ALERT RECEIVED!");
        Serial.println("Confidence: " + String(confidence * 100, 1) + "%");
        
        // Flash LED rapidly for GNN alert
        for(int i = 0; i < 10; i++) {
            digitalWrite(LED_PIN, LOW);
            delay(50);
            digitalWrite(LED_PIN, HIGH);
            delay(50);
        }
    }
    else if (msgType == "status_request") {
        // Send status response
        DynamicJsonDocument response(512);
        response["type"] = "status_response";
        response["node_id"] = nodeId;
        response["wifi_rssi"] = WiFi.RSSI();
        response["free_heap"] = ESP.getFreeHeap();
        response["anomaly_mode"] = anomalyMode;
        response["uptime"] = millis();
        
        String statusMsg;
        serializeJson(response, statusMsg);
        webSocket.sendTXT(statusMsg);
    }
}
