package application;

import java.io.EOFException;
import java.net.Inet4Address;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;

import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Background;
import javafx.scene.layout.BackgroundFill;
import javafx.scene.layout.CornerRadii;
import javafx.scene.paint.Color;
import javafx.stage.Stage;

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
import com.jfoenix.controls.JFXMasonryPane;
import com.jfoenix.controls.JFXTextArea;

public class Controller {

    private static boolean isRunning = false;

    @FXML
    private JFXButton startBtn;

    @FXML
    private JFXTextArea displayArea;

    @FXML
    private JFXMasonryPane displayMasonryPane;

    @FXML
    void onStartBtnClick(ActionEvent event) {
        if (!isRunning) {
            startBtn.setText("停止");
            startBtn.setStyle("-fx-background-color: #FF6200; -fx-text-fill: #ffffff;");
            Thread thread = new Thread() {
                public void run() {
                    while (isRunning) {
                        startCapture();
                    }
                }
            };
            thread.start();
            isRunning = true;
        } else {
            startBtn.setText("开始");
            startBtn.setStyle("-fx-background-color: #2196F3; -fx-text-fill: #ffffff;");
            isRunning = false;
        }
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
                final IpNumber protocol = ipV4Packet.getHeader().getProtocol();
                Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
                Inet4Address dstAddr = ipV4Packet.getHeader().getDstAddr();
                final short length = ipV4Packet.getHeader().getTotalLength();

                if (isRunning) {
                    displayArea.appendText(protocol.name() + " 从 " + srcAddr.getHostAddress() + " 发往 "
                            + dstAddr.getHostAddress() + " 总长度: " + length + "\n");
                }

                Platform.runLater(new Runnable() {
                    public void run() {
                        JFXButton button = new JFXButton(protocol.name());
                        button.setAlignment(Pos.CENTER);
                        button.setPrefWidth(length / 2);
                        button.setTextFill(Color.WHITE);
                        button.setStyle("-fx-font: 14 arial;");

                        Color color;
                        switch (button.getText()) {
                        case "TCP":
                            color = Color.web("#0091EA");
                            break;
                        case "UDP":
                            color = Color.web("#199B18");
                            break;
                        case "ICMPv4":
                            color = Color.web("#E51C17");
                            break;
                        default:
                            color = Color.web("#9E9E9E");
                            break;
                        }

                        button.setBackground(
                                new Background(new BackgroundFill(color, CornerRadii.EMPTY, Insets.EMPTY)));

                        HashMap<JFXButton, IpV4Packet> map = new HashMap<>();
                        map.put(button, ipV4Packet);

                        button.addEventHandler(MouseEvent.MOUSE_CLICKED, (e) -> {
                            AnchorPane root = new AnchorPane();
                            IpV4Packet pkt = map.get(button);
                            String info = getPacketInfo(pkt);

                            Stage stage = new Stage();
                            stage.setResizable(false);
                            stage.setAlwaysOnTop(true);
                            stage.setTitle(pkt.getHeader().getProtocol().name() + " 详情");
                            stage.setScene(new Scene(root, 600, 400));
                            JFXTextArea infoArea = new JFXTextArea();
                            infoArea.setLayoutX(20);
                            infoArea.setLayoutY(20);
                            infoArea.setPrefWidth(560);
                            infoArea.setPrefHeight(360);
                            infoArea.setStyle("-fx-font: 18 'Droid Sans Mono for Powerline';");
                            infoArea.setText(info);
                            root.getChildren().add(infoArea);
                            stage.show();
                        });

                        if (isRunning) {
                            displayMasonryPane.getChildren().add(button);
                        }
                    }
                });
            } catch (NullPointerException e) {
            }

        } catch (PcapNativeException e) {
        } catch (EOFException e) {
        } catch (TimeoutException e) {
        } catch (NotOpenException e) {
        }
        return true;
    }

    private String getPacketInfo(IpV4Packet pkt) {
        String info = "";
        info = info + "版本: " + pkt.getHeader().getVersion() + "\n";
        info = info + "IHL: " + pkt.getHeader().getIhl() + "\n";
        info = info + "区分服务: " + pkt.getHeader().getTos() + "\n";
        info = info + "总长度: " + pkt.getHeader().getTotalLength() + "\n";
        info = info + "标识: " + pkt.getHeader().getIdentification() + "\n";
        info = info + "不分段: " + pkt.getHeader().getDontFragmentFlag() + "\n";
        info = info + "更多分段: " + pkt.getHeader().getMoreFragmentFlag() + "\n";
        info = info + "分段偏移量: " + pkt.getHeader().getFragmentOffset() + "\n";
        info = info + "TTL: " + pkt.getHeader().getTtl() + "\n";
        info = info + "协议: " + pkt.getHeader().getProtocol() + "\n";
        info = info + "头校验和: " + pkt.getHeader().getHeaderChecksum() + "\n";
        info = info + "源地址: " + pkt.getHeader().getSrcAddr().getHostAddress() + "\n";
        info = info + "目标地址: " + pkt.getHeader().getDstAddr().getHostAddress() + "\n";
        info = info + "选项: " + pkt.getHeader().getOptions() + "\n";
        info = info + "\n";
        info = info + "负载: \n" + pkt.getPayload() + "\n";
        return info;
    }
}
