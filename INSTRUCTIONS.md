# Ultra-Low Latency Proxy for Hypixel Skyblock

## What You Need
- Python installed on your computer
- The two files: `proxy_server.py` and `config.json`

## Quick Setup Guide

### Step 1: Put the files in a folder
- Create a new folder on your computer
- Put both files in this folder

### Step 2: Start the proxy server
- Open Command Prompt (Windows) or Terminal (Mac/Linux)
- Navigate to your folder using the `cd` command
  - Example: `cd C:\Users\YourName\Desktop\ProxyFolder`
- Run the proxy server by typing:
  ```
  python proxy_server.py
  ```
- You should see a message saying "Proxy server started on 0.0.0.0:8080"

### Step 3: Configure Minecraft to use the proxy
1. Open Minecraft Launcher
2. Go to Settings/Installations
3. Click on the three dots next to your Hypixel profile
4. Select "Edit"
5. Click "More Options"
6. Find "JVM Arguments" and add this line:
   ```
   -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080 -DsocksProxyHost=127.0.0.1 -DsocksProxyPort=8080
   ```
7. Click "Save"

### Step 4: Play Hypixel Skyblock
- Launch Minecraft with your Hypixel profile
- Connect to mc.hypixel.net
- Your connection will now go through the ultra-low latency proxy

## Ultra-Low Latency Optimizations

This proxy is specifically optimized for Hypixel Skyblock with:

- **TCP_NODELAY**: Disables Nagle's algorithm for faster packet transmission
- **TCP Keepalive**: Maintains connection stability
- **Increased Buffer Size**: 16KB buffer for better performance
- **Reduced Timeout**: 3-second timeout for quicker response
- **Hypixel-Specific Targeting**: Optimized for mc.hypixel.net

## Tips for Best Performance

1. **Use a Wired Connection**: Ethernet is much better than Wi-Fi for low latency
2. **Close Other Applications**: Free up system resources and network bandwidth
3. **Server Location**: Choose Hypixel servers geographically closer to you
4. **Restart Regularly**: Restart the proxy every few hours for optimal performance
5. **System Optimization**:
   - Set your computer's power plan to "High Performance"
   - Disable background applications and services
   - Update your network drivers

## Troubleshooting

- **High Ping**: Make sure you're using a wired connection and close other applications
- **Connection Drops**: Restart the proxy server
- **Can't Connect**: Check that the proxy is running and Minecraft is configured correctly
- **Lag Spikes**: Try restarting both the proxy and Minecraft

## Need to Stop the Proxy?
- Press Ctrl+C in the command window where the proxy is running

## Sharing with Friends
- Send your friend the two files
- Tell them to follow these same steps

That's it! You're now playing Hypixel Skyblock with ultra-low latency through your own proxy server. 