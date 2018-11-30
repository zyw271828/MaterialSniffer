package application;

import java.io.EOFException;
import java.net.Inet4Address;
import java.util.concurrent.TimeoutException;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXTextArea;

public class Controller {

    @FXML
    private JFXButton startBtn;

    @FXML
    private JFXTextArea displayArea;

    @FXML
    void onStartBtnClick(ActionEvent event) {
        Thread thread = new Thread() {
            public void run() {
                while (startCapture()) {
                }
            }
        };
        thread.start();
    }

    private boolean startCapture() {
        try {
            PcapNetworkInterface nif = Pcaps.getDevByName("wlp58s0");
            int snapLen = 65536;
            PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
            int timeout = 10;
            PcapHandle handle = nif.openLive(snapLen, mode, timeout);
            Packet packet = handle.getNextPacketEx();
            handle.close();

            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            try {
                IpNumber protocol = ipV4Packet.getHeader().getProtocol();
                Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
                Inet4Address dstAddr = ipV4Packet.getHeader().getDstAddr();
                short length = ipV4Packet.getHeader().getTotalLength();
                displayArea.appendText(protocol.name() + " Form " + srcAddr.getHostAddress() + " to "
                        + dstAddr.getHostAddress() + " Length: " + length + "\n");
            } catch (NullPointerException e) {
            }

        } catch (PcapNativeException e) {
        } catch (EOFException e) {
        } catch (TimeoutException e) {
        } catch (NotOpenException e) {
        }
        return true;
    }
}
