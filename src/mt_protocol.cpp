#include "mt_internals.h"

// Magic number at the start of all MT packets
#define MT_MAGIC_0 0x94
#define MT_MAGIC_1 0xc3

// The header is the magic number plus a 16-bit payload-length field
#define MT_HEADER_SIZE 4

// The buffer used for protobuf encoding/decoding. Since there's only one, and it's global, we
// have to make sure we're only ever doing one encoding or decoding at a time.
#define PB_BUFSIZE 512
pb_byte_t pb_buf[PB_BUFSIZE+4];
size_t pb_size = 0; // Number of bytes currently in the buffer

// Reasonable minimum and maximum packet sizes for validation
#define MIN_PAYLOAD_SIZE 4      // Minimum plausible payload size
#define MAX_PAYLOAD_SIZE 256    // Maximum reasonable payload size

// Enhanced debugging - enable to dump packet contents during troubleshooting
#define DEBUG_DUMP_PACKETS false

// Statistics for monitoring packet processing - defined here but declared extern in mt_internals.h
uint32_t packets_processed = 0;
uint32_t packets_dropped = 0;
uint32_t resync_attempts = 0;
uint32_t resync_successful = 0;

// Nonce to request only my nodeinfo and skip other nodes in the db
#define SPECIAL_NONCE 69420

// Wait this many msec if there's nothing new on the channel
#define NO_NEWS_PAUSE 25

// Serial connections require at least one ping every 15 minutes
// Otherwise the connection is closed, and packets will no longer be received
// We will send a ping every 60 seconds, which is what the web client does
// https://github.com/meshtastic/js/blob/715e35d2374276a43ffa93c628e3710875d43907/src/adapters/serialConnection.ts#L160
#define HEARTBEAT_INTERVAL_MS 30000  // Reduced from 60s to 30s for more frequent keepalives
uint32_t last_heartbeat_at = 0;

// The ID of the current WANT_CONFIG request
uint32_t want_config_id = 0;

// Node number of the MT node hosting our WiFi
uint32_t my_node_num = 0;

bool mt_debugging = false;
void (*text_message_callback)(uint32_t from, uint32_t to,  uint8_t channel, const char* text) = NULL;
void (*node_report_callback)(mt_node_t *, mt_nr_progress_t) = NULL;
mt_node_t node;

bool mt_wifi_mode = false;
bool mt_serial_mode = false;

void d(const char * s) {
  if (mt_debugging) Serial.println(s);
}

void mt_set_debug(bool on) {
  mt_debugging = on;
}

bool mt_send_radio(const char * buf, size_t len) {
  if (mt_wifi_mode) {
    #ifdef MT_WIFI_SUPPORTED
    return mt_wifi_send_radio(buf, len);
    #else
    return false;
    #endif
  } else if (mt_serial_mode) {
    return mt_serial_send_radio(buf, len);
  } else {
    Serial.println("mt_send_radio() called but it was never initialized");
    while(1);
  }
}

bool _mt_send_toRadio(meshtastic_ToRadio toRadio) {
  pb_buf[0] = MT_MAGIC_0;
  pb_buf[1] = MT_MAGIC_1;

  pb_ostream_t stream = pb_ostream_from_buffer(pb_buf + 4, PB_BUFSIZE);
  bool status = pb_encode(&stream, meshtastic_ToRadio_fields, &toRadio);
  if (!status) {
    d("Couldn't encode toRadio");
    return false;
  }

  // Store the payload length in the header
  pb_buf[2] = stream.bytes_written / 256;
  pb_buf[3] = stream.bytes_written % 256;

  bool rv = mt_send_radio((const char *)pb_buf, 4 + stream.bytes_written);

  // Clear the buffer so it can be used to hold reply packets
  pb_size = 0;

  return rv;
}

// Request a node report from our MT
bool mt_request_node_report(void (*callback)(mt_node_t *, mt_nr_progress_t)) {
  meshtastic_ToRadio toRadio = meshtastic_ToRadio_init_default;
  toRadio.which_payload_variant = meshtastic_ToRadio_want_config_id_tag;
  want_config_id = random(0x7FffFFff);  // random() can't handle anything bigger
  toRadio.want_config_id = want_config_id;

  if (mt_debugging) {
    Serial.print("Requesting node report with random ID ");
    Serial.println(want_config_id);
  }

  bool rv = _mt_send_toRadio(toRadio);

  if (rv) node_report_callback = callback;
  return rv;
}

bool mt_send_text(const char * text, uint32_t dest, uint8_t channel_index) {
  meshtastic_MeshPacket meshPacket = meshtastic_MeshPacket_init_default;
  meshPacket.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
  meshPacket.id = random(0x7FFFFFFF);
  meshPacket.decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
  meshPacket.to = dest;
  meshPacket.channel = channel_index;
  meshPacket.want_ack = true;
  meshPacket.decoded.payload.size = strlen(text);
  memcpy(meshPacket.decoded.payload.bytes, text, meshPacket.decoded.payload.size);

  meshtastic_ToRadio toRadio = meshtastic_ToRadio_init_default;
  toRadio.which_payload_variant = meshtastic_ToRadio_packet_tag;
  toRadio.packet = meshPacket;
  
  Serial.print("Sending text message '");
  Serial.print(text);
  Serial.print("' to ");
  Serial.println(dest);
  return _mt_send_toRadio(toRadio);
}

bool mt_send_heartbeat() {

  d("Sending heartbeat");

  meshtastic_ToRadio toRadio = meshtastic_ToRadio_init_default;
  toRadio.which_payload_variant = meshtastic_ToRadio_heartbeat_tag;
  toRadio.heartbeat = meshtastic_Heartbeat_init_default;

  return _mt_send_toRadio(toRadio);

}

void set_text_message_callback(void (*callback)(uint32_t from, uint32_t to,  uint8_t channel, const char* text)) {
  text_message_callback = callback;
}

bool handle_my_info(meshtastic_MyNodeInfo *myNodeInfo) {
  my_node_num = myNodeInfo->my_node_num;
  return true;
}

bool handle_node_info(meshtastic_NodeInfo *nodeInfo) {
  if (node_report_callback == NULL) {
    d("Got a node report, but we don't have a callback");
    return false;
  }
  node.node_num = nodeInfo->num;
  node.is_mine = nodeInfo->num == my_node_num;
  node.last_heard_from = nodeInfo->last_heard;
  node.has_user = nodeInfo->has_user;
  if (node.has_user) {
    memcpy(node.user_id, nodeInfo->user.id, MAX_USER_ID_LEN);
    memcpy(node.long_name, nodeInfo->user.long_name, MAX_LONG_NAME_LEN);
    memcpy(node.short_name, nodeInfo->user.short_name, MAX_SHORT_NAME_LEN);
  }

  if (nodeInfo->has_position) {
    node.latitude = nodeInfo->position.latitude_i / 1e7;
    node.longitude = nodeInfo->position.longitude_i / 1e7;
    node.altitude = nodeInfo->position.altitude;
    node.ground_speed = nodeInfo->position.ground_speed;
    node.last_heard_position = nodeInfo->position.time;
    node.time_of_last_position = nodeInfo->position.timestamp;
  } else {
    node.latitude = NAN;
    node.longitude = NAN;
    node.altitude = 0;
    node.ground_speed = 0;
    node.battery_level = 0;
    node.last_heard_position = 0;
    node.time_of_last_position = 0;
  }
  if (nodeInfo->has_device_metrics) {
    node.battery_level = nodeInfo->device_metrics.battery_level;
    node.voltage = nodeInfo->device_metrics.voltage;
    node.channel_utilization = nodeInfo->device_metrics.channel_utilization;
    node.air_util_tx = nodeInfo->device_metrics.air_util_tx;
  } else {
    node.battery_level = 0;
    node.voltage = NAN;
    node.channel_utilization = NAN; 
    node.air_util_tx = NAN;
  }

  node_report_callback(&node, MT_NR_IN_PROGRESS);
  return true;
}

bool handle_config_complete_id(uint32_t now, uint32_t config_complete_id) {
  if (config_complete_id == want_config_id) {
    #ifdef MT_WIFI_SUPPORTED
    mt_wifi_reset_idle_timeout(now);  // It's fine if we're actually in serial mode
    #endif
    want_config_id = 0;
    node_report_callback(NULL, MT_NR_DONE);
    node_report_callback = NULL;
  } else {
    node_report_callback(NULL, MT_NR_INVALID);  // but return true, since it was still a valid packet
  }
  return true;
}

/**
 * Handle a mesh packet, which could contain text messages or other data
 * 
 * @param meshPacket Pointer to the mesh packet structure
 * @return boolean indicating if packet was successfully handled
 */
bool handle_mesh_packet(meshtastic_MeshPacket *meshPacket) {
  // Check if it's a decoded payload type
  if (meshPacket->which_payload_variant == meshtastic_MeshPacket_decoded_tag) {
    // Log detailed packet information when debugging
    if (mt_debugging) {
      Serial.print("Packet details: from=0x");
      Serial.print(meshPacket->from, HEX);
      Serial.print(" to=0x");
      Serial.print(meshPacket->to, HEX); 
      Serial.print(" channel=");
      Serial.print(meshPacket->channel);
      Serial.print(" portnum=");
      Serial.print(meshPacket->decoded.portnum);
      
      if (meshPacket->decoded.payload.size > 0) {
        Serial.print(" payload='");
        // Print up to 20 chars of the payload for debugging
        char payload_preview[21] = {0};
        strncpy(payload_preview, (const char*)meshPacket->decoded.payload.bytes, 
               min(20, (int)meshPacket->decoded.payload.size));
        Serial.print(payload_preview);
        Serial.println("'");
      } else {
        Serial.println(" (empty payload)");
      }
    }
    
    // Handle text messages (this is what carries the "12345" test message)
    if (meshPacket->decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP) {
      if (mt_debugging) {
        Serial.println("Text message detected - calling message callback");
      }
      
      if (text_message_callback != NULL) {
        // Call the message callback which handles ACK and cloud publishing
        text_message_callback(
          meshPacket->from, 
          meshPacket->to, 
          meshPacket->channel, 
          (const char*)meshPacket->decoded.payload.bytes
        );
        return true;
      } else {
        if (mt_debugging) {
          Serial.println("ERROR: Text message received but no callback registered!");
        }
        return false;
      }
    } else {
      if (mt_debugging) {
        Serial.print("Unhandled portnum: ");
        Serial.println(meshPacket->decoded.portnum);
      }
      // TODO handle other portnums
      return false;
    }
  } else {
    if (mt_debugging) {
      Serial.print("Unhandled payload variant in mesh packet: ");
      Serial.println(meshPacket->which_payload_variant);
    }
    return false;
  }
}

/**
 * Parse a packet that came in, and handle it based on its payload variant.
 * 
 * This function:
 * 1. Decodes protobuf messages from the buffer
 * 2. Handles various message types based on payload variants
 * 3. Provides detailed error handling and logging
 * 4. Support for log records and other important message types
 * 
 * @param now Current timestamp in milliseconds
 * @param payload_len Length of the payload to process
 * @return true if successfully handled, false if error or unknown type
 */
bool handle_packet(uint32_t now, size_t payload_len) {
  meshtastic_FromRadio fromRadio = meshtastic_FromRadio_init_zero;

  // Save a copy of the original buffer for diagnostic purposes in case of decode failure
  pb_byte_t original_bytes[16];
  if (mt_debugging) {
    // Save at most 16 bytes for diagnostics
    size_t bytes_to_copy = min(16, (int)payload_len);
    memcpy(original_bytes, pb_buf + 4, bytes_to_copy);
  }

  // Decode the protobuf and shift forward any remaining bytes in the buffer
  pb_istream_t stream = pb_istream_from_buffer(pb_buf + 4, payload_len);
  bool status = pb_decode(&stream, meshtastic_FromRadio_fields, &fromRadio);
  
  // Move any remaining data to the beginning of the buffer for next processing cycle
  size_t safe_move_length = min(PB_BUFSIZE - 4 - payload_len, pb_size - 4 - payload_len);
  if (safe_move_length > 0 && safe_move_length < PB_BUFSIZE) {
    memmove(pb_buf, pb_buf + 4 + payload_len, safe_move_length);
  }
  pb_size -= 4 + payload_len;

  // Be prepared to request a node report to re-establish flow after an MT reboot
  meshtastic_ToRadio toRadio = meshtastic_ToRadio_init_default;
  toRadio.which_payload_variant = meshtastic_ToRadio_want_config_id_tag;
  toRadio.want_config_id = SPECIAL_NONCE;

  if (!status) {
    // ALWAYS log decode failures - this is critical for diagnosing the problem
    Serial.println("CRITICAL: Protobuf decoding failed");
    Serial.print("Failed packet bytes: ");
    for (int i = 0; i < min(16, (int)payload_len); i++) {
      Serial.print(original_bytes[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
    
    // Try to force a node report request after decode failures
    // This often helps re-establish communication
    Serial.println("RECOVERY: Requesting node report after decode failure");
    _mt_send_toRadio(toRadio);
    
    return false;
  }

  // Handle the specific payload variant
  switch (fromRadio.which_payload_variant) {
    case meshtastic_FromRadio_my_info_tag:
      if (mt_debugging) {
        Serial.println("Received my_info message");
      }
      return handle_my_info(&fromRadio.my_info);
      
    case meshtastic_FromRadio_node_info_tag:
      if (mt_debugging) {
        Serial.println("Received node_info message");
      }
      return handle_node_info(&fromRadio.node_info);
      
    case meshtastic_FromRadio_config_complete_id_tag:
      if (mt_debugging) {
        Serial.println("Received config_complete_id message");
      }
      return handle_config_complete_id(now, fromRadio.config_complete_id);
      
    case meshtastic_FromRadio_packet_tag:
      if (mt_debugging) {
        Serial.println("Received packet message");
      }
      return handle_mesh_packet(&fromRadio.packet);
      
    case meshtastic_FromRadio_rebooted_tag:
      if (mt_debugging) {
        Serial.println("Received rebooted message - requesting node config");
      }
      return _mt_send_toRadio(toRadio);
    
    // Log record message (payload variant 11)
    case 11: // meshtastic_FromRadio_log_record_tag:
      if (mt_debugging) {
        Serial.println("Received log_record message");
        
        // For this device's firmware version, we just need to acknowledge the log record
        // The actual structure may vary between firmware versions, so we keep it simple
        Serial.println("Log record received and handled");
      }
      return true; // Successfully handled
      
    default:
      if (mt_debugging) {
        // Rate limit
        constexpr uint32_t limitMs = 100; 
        static uint32_t lastLog = 0;
        uint32_t current_time = millis();
        if (current_time - lastLog > limitMs) {
            lastLog = current_time;
            Serial.print("Unknown payload variant: ");
            Serial.println(fromRadio.which_payload_variant);
        }
      }
      return false;
  }
}

/**
 * Check for and process complete packets in the buffer
 * 
 * This function handles:
 * 1. Checking for complete packet headers
 * 2. Validating magic numbers
 * 3. Attempting to resynchronize after errors
 * 4. Validating packet lengths
 * 5. Processing complete packets
 * 
 * @param now Current timestamp in milliseconds
 */
void mt_protocol_check_packet(uint32_t now) {
  if (pb_size < MT_HEADER_SIZE) {
    // We don't even have a complete header yet
    delay(NO_NEWS_PAUSE);
    return;
  }

  // Check for valid magic numbers
  if (pb_buf[0] != MT_MAGIC_0 || pb_buf[1] != MT_MAGIC_1) {
    // Magic numbers don't match - attempt to resynchronize
    if (mt_debugging) {
      Serial.print("Got bad magic: ");
      Serial.print(pb_buf[0], HEX);
      Serial.print(" ");
      Serial.print(pb_buf[1], HEX);
      Serial.println(" - attempting resynchronization");
      
      // Print buffer content for advanced debugging
      Serial.print("Buffer content (first 24 bytes): ");
      for (int i = 0; i < min(24, (int)pb_size); i++) {
        Serial.print(pb_buf[i], HEX);
        Serial.print(" ");
      }
      Serial.println();
    }
    
    resync_attempts++;
    
    // Enhanced resync strategy: analyze in chunks for better reliability
    // We'll check for multiple potential magic number sequences
    
    // First, check for any direct magic number occurrences
    bool found_magic = false;
    
    // Two-pass approach to maximize chances of finding valid frames
    // Pass 1: Look for standard magic bytes in sequence
    for (size_t i = 1; i < pb_size - 1; i++) {
      if (pb_buf[i] == MT_MAGIC_0 && pb_buf[i+1] == MT_MAGIC_1) {
        // Verify this is likely a real packet - check if length field is reasonable
        if (i+3 < pb_size) {
          uint16_t potential_len = pb_buf[i+2] << 8 | pb_buf[i+3];
          
          // If length is reasonable, we're more confident this is a packet start
          if (potential_len < MAX_PAYLOAD_SIZE && potential_len >= MIN_PAYLOAD_SIZE) {
            if (mt_debugging) {
              Serial.print("Found highly likely magic at offset ");
              Serial.print(i);
              Serial.print(" with length ");
              Serial.println(potential_len);
            }
            
            // Shift buffer to align with found magic bytes
            memmove(pb_buf, pb_buf + i, pb_size - i);
            pb_size -= i;
            found_magic = true;
            resync_successful++;
            break;
          }
        } else {
          // Can't check length but we did find magic - let's try this position
          if (mt_debugging) {
            Serial.print("Found potential magic at offset ");
            Serial.println(i);
          }
          
          // Shift buffer to align with found magic bytes
          memmove(pb_buf, pb_buf + i, pb_size - i);
          pb_size -= i;
          found_magic = true;
          resync_successful++;
          break;
        }
      }
    }
    
    // Pass 2: If still not found, be less strict and just align on any magic bytes
    if (!found_magic) {
      for (size_t i = 1; i < pb_size - 1; i++) {
        if (pb_buf[i] == MT_MAGIC_0 && pb_buf[i+1] == MT_MAGIC_1) {
          if (mt_debugging) {
            Serial.print("Found backup magic at offset ");
            Serial.println(i);
          }
          
          // Shift buffer to align with found magic bytes
          memmove(pb_buf, pb_buf + i, pb_size - i);
          pb_size -= i;
          found_magic = true;
          resync_successful++;
          break;
        }
      }
    }
    
    if (!found_magic) {
      // More aggressive strategy: If we can't find the exact sequence,
      // let's consider dropping just the first byte and trying again next time
      if (pb_size > 2) {
        if (mt_debugging) {
          Serial.println("No magic found - shifting buffer by 1 byte to continue search");
        }
        memmove(pb_buf, pb_buf + 1, pb_size - 1);
        pb_size -= 1;
      } else {
        // Buffer too small - just clear it
        if (mt_debugging) {
          Serial.println("No magic found in buffer - clearing");
        }
        memset(pb_buf, 0, PB_BUFSIZE);
        pb_size = 0;
        packets_dropped++;
      }
    }
    
    // Request node report after several failed attempts
    static uint8_t consecutive_failed_attempts = 0;
    if (!found_magic) {
      consecutive_failed_attempts++;
      if (consecutive_failed_attempts >= 5) {
        Serial.println("Multiple sync failures - requesting node report to reestablish");
        meshtastic_ToRadio toRadio = meshtastic_ToRadio_init_default;
        toRadio.which_payload_variant = meshtastic_ToRadio_want_config_id_tag;
        toRadio.want_config_id = SPECIAL_NONCE;
        _mt_send_toRadio(toRadio);
        consecutive_failed_attempts = 0;
      }
    } else {
      consecutive_failed_attempts = 0;
    }
    
    // After resync attempt, wait for more data
    delay(NO_NEWS_PAUSE);
    return;
  }

  // Extract and validate payload length
  uint16_t payload_len = pb_buf[2] << 8 | pb_buf[3];
  
  // CRITICAL DIAGNOSTIC: Always log the first few packets we receive
  static uint8_t packet_log_count = 0;
  if (packet_log_count < 5) {
    packet_log_count++;
    Serial.print("PACKET ANALYSIS #");
    Serial.print(packet_log_count);
    Serial.print(": Magic=");
    Serial.print(pb_buf[0], HEX);
    Serial.print(",");
    Serial.print(pb_buf[1], HEX);
    Serial.print(" Length=");
    Serial.print(payload_len);
    Serial.print(" First 16 bytes: ");
    for (int i = 0; i < min(16, (int)pb_size); i++) {
      Serial.print(pb_buf[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
  
  // Perform sanity checks on payload length
  if (payload_len < MIN_PAYLOAD_SIZE || payload_len > MAX_PAYLOAD_SIZE) {
    Serial.print("INVALID LENGTH: ");
    Serial.print(payload_len);
    Serial.println(" - discarding header and continuing");
    
    // Print the first few bytes to help diagnose issues
    Serial.print("Header bytes: ");
    for (int i = 0; i < min(16, (int)pb_size); i++) {
      Serial.print(pb_buf[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
    
    // Skip past this corrupted header and look for next potential packet
    memmove(pb_buf, pb_buf + 4, pb_size - 4);
    pb_size -= 4;
    packets_dropped++;
    return;
  }

  // Check if we have a complete packet
  if ((size_t)(payload_len + 4) > pb_size) {
    // Incomplete packet - wait for more data
    delay(NO_NEWS_PAUSE);
    return;
  }

  // We have a complete, valid packet - optionally dump it for debugging
  if (mt_debugging && DEBUG_DUMP_PACKETS) {
    Serial.print("Processing packet: len=");
    Serial.print(payload_len);
    Serial.print(" bytes: ");
    for (int i = 0; i < min((int)(payload_len + 4), 24); i++) {
      Serial.print(pb_buf[i], HEX);
      Serial.print(" ");
    }
    if (payload_len + 4 > 24) {
      Serial.print("...");
    }
    Serial.println();
  }

  // Process the packet
  bool success = handle_packet(now, payload_len);
  if (success) {
    packets_processed++;
  } else {
    packets_dropped++;
  }
}

/**
 * Main processing loop for Meshtastic protocol
 * 
 * This function:
 * 1. Checks for new data from radio
 * 2. Processes received packets
 * 3. Handles heartbeat timing
 * 4. Provides diagnostic statistics when debugging
 * 
 * @param now Current timestamp in milliseconds
 * @return Boolean indicating if connection is ready
 */
bool mt_loop(uint32_t now) {
  static uint32_t last_stats_time = 0;
  bool rv;
  size_t bytes_read = 0;

  // See if there are any more bytes to add to our buffer.
  size_t space_left = PB_BUFSIZE - pb_size;
  
  // Check if buffer is close to full - log warning if debugging
  if (space_left < 32 && mt_debugging) {
    Serial.print("WARNING: Buffer nearly full - only ");
    Serial.print(space_left);
    Serial.println(" bytes left");
  }
 
  if (mt_wifi_mode) {
#ifdef MT_WIFI_SUPPORTED
    rv = mt_wifi_loop(now);
    if (rv) bytes_read = mt_wifi_check_radio((char *)pb_buf + pb_size, space_left);
#else
    return false;
#endif
  } else if (mt_serial_mode) {
    rv = mt_serial_loop();
    if (rv) bytes_read = mt_serial_check_radio((char *)pb_buf + pb_size, space_left);

    // Send heartbeat if interval has passed to keep serial connection alive
    if(now >= (last_heartbeat_at + HEARTBEAT_INTERVAL_MS)){
        if (mt_debugging) {
          Serial.println("Sending periodic heartbeat");
        }
        mt_send_heartbeat();
        last_heartbeat_at = now;
    }
  } else {
    Serial.println("mt_loop() called but it was never initialized");
    while(1);
  }

  // Update buffer size and process any packets
  pb_size += bytes_read;
  mt_protocol_check_packet(now);
  
  // Periodically output debug statistics if debugging enabled (every 30 seconds)
  if (mt_debugging && (now - last_stats_time > 30000)) {
    last_stats_time = now;
    
    Serial.println("\n--- Meshtastic Protocol Statistics ---");
    Serial.print("Packets processed: ");
    Serial.println(packets_processed);
    Serial.print("Packets dropped: ");
    Serial.println(packets_dropped);
    Serial.print("Buffer resync attempts: ");
    Serial.println(resync_attempts);
    Serial.print("Successful resyncs: ");
    Serial.println(resync_successful);
    Serial.print("Current buffer usage: ");
    Serial.print(pb_size);
    Serial.print("/");
    Serial.println(PB_BUFSIZE);
    Serial.println("--------------------------------------\n");
  }
  
  return rv;
}
