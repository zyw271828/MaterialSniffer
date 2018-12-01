package application;

import java.io.EOFException;
import java.net.Inet4Address;
import java.util.HashMap;
import java.util.List;
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
import com.jfoenix.controls.JFXButton.ButtonType;

public class Controller {

    private static boolean isRunning = false;
    private static PcapNetworkInterface networkInterface = null;

    @FXML
    private JFXButton startBtn;

    @FXML
    private JFXButton changeBtn;

    @FXML
    private JFXTextArea displayArea;

    @FXML
    private JFXMasonryPane displayMasonryPane;

    @FXML
    public void initialize() {

        displayArea.setStyle("-fx-font: 20 'Droid Sans Mono for Powerline';");

        try {
            List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
            PcapNetworkInterface nif = nifs.get(0);
            networkInterface = nif;
            displayArea.appendText("设置网络接口: " + networkInterface.getName() + "\n");
        } catch (PcapNativeException e) {
            displayArea.appendText("查找网络接口时出现错误\n");
        }
    }

    @FXML
    void onStartBtnClick(ActionEvent event) {
        if (!isRunning) {
            startBtn.setText("停止");
            startBtn.setStyle("-fx-background-color: #FF6200; -fx-text-fill: #FFFFFF;");
            changeBtn.setDisable(true);
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
            startBtn.setStyle("-fx-background-color: #2196F3; -fx-text-fill: #FFFFFF;");
            changeBtn.setDisable(false);
            isRunning = false;
        }
    }

    private boolean startCapture() {
        try {
            PcapNetworkInterface nif = networkInterface;
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
                        button.setButtonType(ButtonType.RAISED);
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
                        case "IGMP":
                            color = Color.web("#9C1BB0");
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
                            root.setBackground(button.getBackground());
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
                            infoArea.setBackground(button.getBackground());
                            infoArea.setFocusColor(color);
                            infoArea.setStyle("-fx-font: 20 'Droid Sans Mono for Powerline'; -fx-text-fill: #FFFFFF;");
                            infoArea.getStylesheets()
                                    .add(Controller.class.getResource("ScrollPane.css").toExternalForm());
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

    @FXML
    void onChangeBtnClick(ActionEvent event) {
        nextNetworkInterface();
    }

    private void nextNetworkInterface() { // 循环更换接口
        try {
            List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();

            for (int i = 0; i < nifs.size(); i++) {
                if (!networkInterface.getName().equals(nifs.get(i).getName())) {
                    continue; // 没有找到当前接口
                } else { // 找到了当前接口
                    if (i == nifs.size() - 1) { // 是最后一个
                        networkInterface = nifs.get(0); // 设置接口为第一个
                        break; // 设置完毕
                    } else { // 不是最后一个
                        networkInterface = nifs.get(i + 1); // 设置接口为下一个
                        break; // 设置完毕
                    }
                }
            }
            displayArea.appendText("设置网络接口: " + networkInterface.getName() + "\n");
        } catch (NullPointerException e) {
        } catch (PcapNativeException e) {
        }
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
