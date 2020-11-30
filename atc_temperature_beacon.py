"""
Simple BLE forever-scan example, that prints all the detected
LE advertisement packets, and prints a colored diff of data on data changes.
"""
import sys
import bluetooth._bluetooth as bluez
import struct
import paho.mqtt.client as mqtt
import ssl
import time

from bluetooth_utils import (toggle_device,
                             enable_le_scan, parse_le_advertising_events,
                             disable_le_scan, raw_packet_to_str)




# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("dlpublisher/control/#")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

#MQTT parameters
SERVER_ADDRESS = "sctdf.com.br"
SERVER_PORT = 8883
TLS_CERT_PATH="atc_beacon.pem"

#bluetooth parameters
dev_id = 0  # the bluetooth device is hci0
toggle_device(dev_id, True)
mac_addresses = ['A4:C1:38:29:9C:E1', 'A4:C1:38:28:EE:36', 'A4:C1:38:D6:2B:3C']
last_seq_no = {}

#MQTT connection
mqtt_client = mqtt.Client()
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.tls_set(ca_certs=TLS_CERT_PATH, certfile=None,
                    keyfile=None, cert_reqs=ssl.CERT_NONE,
                    tls_version=ssl.PROTOCOL_TLSv1_2, ciphers=None)
mqtt_client.tls_insecure_set(True) 
#mqtt_client.tls_set(ca_certs=TLS_CERT_PATH, certfile=None, keyfile=None, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLSv1_2, ciphers=None)
#mqtt_client.tls_insecure_set(True)
mqtt_client.username_pw_set(username="",password="")
disconnected = True
while disconnected:
    try:
        mqtt_client.connect(SERVER_ADDRESS, SERVER_PORT, 60)
        disconnected = False
    except:
        time.sleep(2)

# call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
mqtt_client.loop_start()

try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print("Cannot open bluetooth device %i" % dev_id)
    raise

enable_le_scan(sock, filter_duplicates=False)

prev_data = None

try:
    def parse_temp(mac, data, rssi):
        offset = 0    
        ctrl,mac2, temp,hum,volt,volt2,seqno = struct.unpack_from(">5s6sHbbHb", data, offset)               
        if mac not in last_seq_no:
            last_seq_no[mac]=seqno+1        
        
        if last_seq_no[mac]!=seqno:
            mqtt_client.publish("btbeacon/"+mac+"/temperature", temp/10, qos=0, retain=True)
            mqtt_client.publish("btbeacon/"+mac+"/humidity", hum, qos=0, retain=True)
            mqtt_client.publish("btbeacon/"+mac+"/battery/percentage", volt, qos=0, retain=True)
            mqtt_client.publish("btbeacon/"+mac+"/battery/volts", volt2/1000, qos=0, retain=True)
            mqtt_client.publish("btbeacon/"+mac+"/rssi", rssi, qos=0, retain=True)
            last_seq_no[mac]=seqno
        

        

    def le_advertise_packet_handler(mac, adv_type, data, rssi):
        if mac in mac_addresses:
            parse_temp(mac,data,rssi)

        
    # Blocking call (the given handler will be called each time a new LE
    # advertisement packet is detected)
    parse_le_advertising_events(sock, handler=le_advertise_packet_handler,  debug=False)
except KeyboardInterrupt:
    disable_le_scan(sock)
