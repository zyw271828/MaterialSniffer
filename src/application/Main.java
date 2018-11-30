package application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;

public class Main extends Application {
    public void start(Stage primaryStage) {
        try {
            Parent root = (Parent) FXMLLoader.load(getClass().getResource("WindowView.fxml"));
            Scene scene = new Scene(root, 1024, 768);
            primaryStage.setTitle("MaterialSniffer");
            primaryStage.setScene(scene);
            primaryStage.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
