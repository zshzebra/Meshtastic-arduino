#include "mt_internals.h"

// Platform specific: select serial
#if defined(ARDUINO_ARCH_SAMD)
#define serial (&Serial1)
#elif defined(ARDUINO_ARCH_ESP32)
#define serial (&Serial1)
#else
#define serial (&Serial1)
#endif /* #if defined(ARDUINO_ARCH_SAMD) */

/**
 * Initialize serial communication with the Meshtastic device
 * 
 * @param rx_pin RX pin for serial communication
 * @param tx_pin TX pin for serial communication
 * @param baud Baud rate for serial communication
 */
void mt_serial_init(int8_t rx_pin, int8_t tx_pin, uint32_t baud)
{
    // First ensure any existing serial connection is closed
    serial->end();
    
    // Allow time for serial port to reset
    delay(100);
    
    // Platform specific: init serial with specific settings
    // Using 8N1 (8 data bits, no parity, 1 stop bit) - default format for Meshtastic
#if defined(ARDUINO_ARCH_SAMD)
    serial->begin(baud);
#elif defined(ARDUINO_ARCH_ESP32)
    serial->begin(baud, SERIAL_8N1, rx_pin, tx_pin);
#else
    serial->begin(baud);
#endif /* #if defined(ARDUINO_ARCH_SAMD) */

    // Ensure all buffers are clear before starting
    while (serial->available()) {
        serial->read(); // Flush any pending data
    }
    
    // Set mode flags
    mt_wifi_mode = false;
    mt_serial_mode = true;
    
    // Log initialization
    Serial.print("Serial interface initialized at ");
    Serial.print(baud);
    Serial.println(" baud");
    
    // Reset statistics for new connection
    packets_processed = 0;
    packets_dropped = 0;
    resync_attempts = 0;
    resync_successful = 0;
}

bool mt_serial_send_radio(const char *buf, size_t len)
{
    size_t wrote = serial->write((const uint8_t *)buf, len);
    if (wrote == len)
        return true;

    if (mt_debugging)
    {
        Serial.print("Tried to send radio ");
        Serial.print(len);
        Serial.print(" but actually sent ");
        Serial.println(wrote);
    }

    return false;
}

bool mt_serial_loop()
{
    return true; // It's easy being a serial interface
}

/**
 * Check for and read incoming data from the serial radio interface
 * 
 * @param buf Buffer to store incoming data
 * @param space_left Available space in the buffer
 * @return Number of bytes read
 */
size_t mt_serial_check_radio(char *buf, size_t space_left)
{
    size_t bytes_read = 0;
    
    // Log when we have data available
    if (serial->available() > 0 && mt_debugging) {
        Serial.print("SERIAL: ");
        Serial.print(serial->available());
        Serial.println(" bytes available to read");
    }
    
    // Safety check - if space left is too small, log a warning
    if (space_left < 32 && (size_t)serial->available() > space_left) {
        Serial.print("WARNING: Buffer nearly full (");
        Serial.print(space_left);
        Serial.print(" bytes left) but ");
        Serial.print(serial->available());
        Serial.println(" bytes available - potential overflow");
    }
    
    // Read available bytes from serial port
    while (serial->available())
    {
        char c = serial->read();
        
        // Option to log first few bytes for debugging
        static bool first_bytes = true;
        if (first_bytes && bytes_read < 16) {
            Serial.print(c, HEX);
            Serial.print(" ");
            if (bytes_read == 15) {
                Serial.println();
                first_bytes = false;
            }
        }
        
        // Store the byte in buffer
        *buf++ = c;
        
        // Check for buffer overflow
        if (++bytes_read >= space_left)
        {
            Serial.println("CRITICAL: Serial buffer overflow - some data will be lost");
            // Flush remaining input
            while (serial->available()) {
                serial->read();
            }
            break;
        }
    }
    
    // Log bytes read for diagnosis
    if (bytes_read > 0 && mt_debugging) {
        Serial.print("SERIAL: Read ");
        Serial.print(bytes_read);
        Serial.println(" bytes");
    }
    
    return bytes_read;
}
