# MaterialSniffer
A Material Design network sniffer.

## Build
### For Linux:
* Install libpcap-dev, OpenJDK 11, OpenJFX 11  
`sudo apt-get install libpcap-dev openjdk-11-jdk openjfx`

* Capture packets with a non-root user  
`sudo setcap cap_net_raw,cap_net_admin=eip /path/to/bin/java`  
For example:  
`sudo setcap cap_net_raw,cap_net_admin=eip /usr/lib/jvm/java-11-openjdk-amd64/bin/java`

### For Windows:
* [WinPcap](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe)
* [OpenJDK](https://download.java.net/java/GA/jdk11/13/GPL/openjdk-11.0.1_windows-x64_bin.zip)
* [JavaFX SDK](http://gluonhq.com/download/javafx-11-0-1-sdk-windows/)

## License
MaterialSniffer is licensed under the GNU General Public License v3.0
