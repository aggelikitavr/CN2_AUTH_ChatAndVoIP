package com.cn2.communication;

import java.io.*;
import java.net.*;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.*;
import java.awt.event.*;
import java.awt.Color;
import java.lang.Thread;

import javax.sound.sampled.*;

public class App extends Frame implements WindowListener, ActionListener {
	
	// GUI components
    static TextField ipTextField;
    static TextField inputTextField;
    static JTextArea textArea;
    static JFrame frame;
    static JButton sendButton;
    static JTextField messageTextField;
    public static Color gray;
    final static String newline = "\n";
    static JButton callButton;

    // Networking components
    private DatagramSocket sendSocket;
    private DatagramSocket receiveSocket;
    private final int port = 12345; // Fixed port for both sending and receiving

    // Audio components
    private TargetDataLine microphone;
    private SourceDataLine speaker;
    private AudioFormat audioFormat;

    // Buffer size
    private final int bufferSize = 1024;

    // Call management
    private boolean callActive = false; // To track if a call is active
    private Thread callThread; // Thread for managing the call

     // Construct the app's frame and initialize important parameters
    public App(String title) {

        super(title);
        gray = new Color(254, 254, 254);
        setBackground(gray);
        setLayout(new FlowLayout());
        addWindowListener(this);
        
        // chatSphere logo
    	ImageIcon icon = new ImageIcon(getClass().getResource("/image/chatSphere_logo.png")); // Image path
        setIconImage(icon.getImage());

        // Setting up the TextField and the TextArea
        ipTextField = new TextField();
        ipTextField.setColumns(15);
        inputTextField = new TextField();
        inputTextField.setColumns(20);

        textArea = new JTextArea(10, 40);
        textArea.setLineWrap(true);
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // Setting up the buttons
        sendButton = new JButton("Send");
        callButton = new JButton("Call");

        // Adding components to the GUI
        add(scrollPane);
        add(new Label("IP Address:"));
        add(ipTextField);
        add(inputTextField);
        add(sendButton);
        add(callButton);

        // Linking buttons to the ActionListener
        sendButton.addActionListener(this);
        callButton.addActionListener(this);

        // Initialize networking
        try {
            sendSocket = new DatagramSocket();
            receiveSocket = new DatagramSocket(port);
        } catch (SocketException e) {
            System.err.println("Error initializing sockets: " + e.getMessage());
        }

        // Set up audio format
        audioFormat = new AudioFormat(8000.0f, 8, 1, true, true);

        // Start receiving messages
        new Thread(this::receiveMessages).start();
    }

    public static void main(String[] args) {
        App app = new App("chatSphere - AUTH");
        app.setSize(500, 300);
        app.setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
    	// check which button was clicked
        if (e.getSource() == sendButton) {
            sendMessage();
        } else if (e.getSource() == callButton) {
            if (callActive) {
                endCall(); // End the call
            } else {
                startCall(); // Start a new call
            }
        }
    }

    private void sendMessage() {
        String message = inputTextField.getText();
        String remoteIP = ipTextField.getText();

        if (message.isEmpty()) return;

        if (remoteIP.isEmpty()) {
            textArea.append("Error: No remote IP specified.\n");
            return;
        }

        try {
            byte[] buffer = message.getBytes();
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, InetAddress.getByName(remoteIP), port);
            sendSocket.send(packet);
            textArea.append("Aggeliki: " + message + "\n");
            inputTextField.setText("");
        } catch (IOException ex) {
            System.err.println("Error sending message: " + ex.getMessage());
        }
    }

    private void receiveMessages() {
        byte[] buffer = new byte[bufferSize];
        try {
            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiveSocket.receive(packet);

                String message = new String(packet.getData(), 0, packet.getLength());

                if (isTextMessage(message)) {
                    textArea.append("Lena: " + message + "\n");
                }
            }
        } catch (IOException e) {
            System.err.println("Error receiving messages: " + e.getMessage());
        }
    }

    private boolean isTextMessage(String message) {
        return message.chars().allMatch(c -> c >= 32 && c <= 126);
    }

    private void startCall() {
        if (callActive) return; // Prevent starting a new call if one is already active

        callActive = true;
        callThread = new Thread(() -> {
            try {
                String remoteIP = ipTextField.getText();
                if (remoteIP.isEmpty()) {
                    textArea.append("Error: No remote IP specified.\n");
                    callActive = false;
                    return;
                }
                
                textArea.append("Call started!\n");

                microphone = AudioSystem.getTargetDataLine(audioFormat);
                speaker = AudioSystem.getSourceDataLine(audioFormat);

                microphone.open(audioFormat);
                speaker.open(audioFormat);

                microphone.start();
                speaker.start();

                byte[] audioBuffer = new byte[bufferSize];

                // Thread to send audio
                Thread sendAudioThread = new Thread(() -> {
                    try {
                        while (callActive) {
                            int bytesRead = microphone.read(audioBuffer, 0, audioBuffer.length);
                            DatagramPacket packet = new DatagramPacket(audioBuffer, bytesRead, InetAddress.getByName(remoteIP), port);
                            sendSocket.send(packet);
                        }
                    } catch (IOException e) {
                        System.err.println("Error sending audio: " + e.getMessage());
                    }
                });
                sendAudioThread.start();

                // Receive and play audio
                byte[] receiveBuffer = new byte[bufferSize];
                while (callActive) {
                    DatagramPacket packet = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                    receiveSocket.receive(packet);
                    speaker.write(packet.getData(), 0, packet.getLength());
                }

            } catch (LineUnavailableException | IOException e) {
                System.err.println("Error during call: " + e.getMessage());
            } finally {
                endCall(); // Ensure resources are cleaned up
            }
        });
        callThread.start();
    }

    private void endCall() {
        if (!callActive) return;

        callActive = false;
        if (callThread != null && callThread.isAlive()) {
            callThread.interrupt();
        }

        if (microphone != null) {
            microphone.stop();
            microphone.close();
        }

        if (speaker != null) {
            speaker.stop();
            speaker.close();
        }
        
        // closing the sockets when ending the call
        if (sendSocket != null && !sendSocket.isClosed()) {
            sendSocket.close();
        }
        if (receiveSocket != null && !receiveSocket.isClosed()) {
            receiveSocket.close();
        }

        textArea.append("Call ended.\n");
    }

    @Override
    public void windowActivated(WindowEvent e) {}

    @Override
    public void windowClosed(WindowEvent e) {}

    @Override
    public void windowClosing(WindowEvent e) {
    	dispose();
        System.exit(0);
    }

    @Override
    public void windowDeactivated(WindowEvent e) {}

    @Override
    public void windowDeiconified(WindowEvent e) {}

    @Override
    public void windowIconified(WindowEvent e) {}
    
    @Override
    public void windowOpened(WindowEvent e) {}
}
// To change to TCP for P2P Chat, remove the comment symbols from rows 285-463 and make comments the above from rows 22-281
// ------------------------------------------------------------------------------------------------------------------------------------------------
// TCP Implementation
/*
public class App extends Frame implements WindowListener, ActionListener, Runnable {

    // GUI components
    static TextField ipTextField;
    static TextField inputTextField;
    static JTextArea textArea;
    static JFrame frame;
    static JButton sendButton;
    static JTextField messageTextField;
    public static Color gray;
    final static String newline = "\n";

    // Networking components
    private PrintWriter out;
    private BufferedReader in;
    private Socket TCPSocket;
    private ServerSocket serverSocket;
    private boolean isConnected = false;
    private static final int port = 12345; // Fixed port for both sending and receiving

    // Construct the app's frame and initialize important parameters
    public App(String title) {
        super(title);
        gray = new Color(254, 254, 254);
        setBackground(gray);
        setLayout(new FlowLayout());
        addWindowListener(this);

        // chatSphere logo
        ImageIcon icon = new ImageIcon(getClass().getResource("/image/chatSphere_logo.png")); // Image path
        setIconImage(icon.getImage());

        // Setting up the TextField and the TextArea
        ipTextField = new TextField();
        ipTextField.setColumns(15);
        inputTextField = new TextField();
        inputTextField.setColumns(20);

        textArea = new JTextArea(10, 40);
        textArea.setLineWrap(true);
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // Setting up the button
        sendButton = new JButton("Send");

        // Adding components to the GUI
        add(scrollPane);
        add(new Label("IP Address:"));
        add(ipTextField);
        add(inputTextField);
        add(sendButton);

        // Linking button to the ActionListener
        sendButton.addActionListener(this);

        // Initialize networking for TCP and start server listening in a separate thread
        new Thread(this).start();
    }

    public static void main(String[] args) {
        App app = new App("chatSphere - AUTH (TCP)");
        app.setSize(500, 300);
        app.setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // Handle send button action
        if (e.getSource() == sendButton) {
            sendMessage();
        }
    }

    private void sendMessage() {
        String message = inputTextField.getText();
        String remoteIP = ipTextField.getText();

        if (message.isEmpty()) return;

        if (remoteIP.isEmpty()) {
            textArea.append("Error: No remote IP specified.\n");
            return;
        }

        try {
            if (!isConnected) {
                TCPSocket = new Socket(remoteIP, port);
                out = new PrintWriter(TCPSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(TCPSocket.getInputStream()));
                isConnected = true;
                new Thread(this::receiveMessages).start();
            }

            out.println(message);
            textArea.append("Aggeliki: " + message + "\n");
            inputTextField.setText("");
        } catch (IOException ex) {
            textArea.append("Connection failed: " + ex.getMessage() + "\n");
        }
    }
    
    // Receive messages
    private void receiveMessages() {
        try {
            String message;
            while ((message = in.readLine()) != null) {
                textArea.append("Lena: " + message + "\n");
            }
        } catch (IOException e) {
            textArea.append("Error receiving messages: " + e.getMessage() + "\n");
        }
    }

    @Override
    public void run() {
        try {
            serverSocket = new ServerSocket(port);
            textArea.append("Waiting for connections...\n");
            while (true) {
                Socket peerSocket = serverSocket.accept();

                // Create a new thread to handle communication
                new Thread(() -> handleClient(peerSocket)).start();
            }
        } catch (IOException e) {
            textArea.append("Error starting server: " + e.getMessage() + "\n");
        }
    }

    private void handleClient(Socket peerSocket) {
        try {
            BufferedReader peerIn = new BufferedReader(new InputStreamReader(peerSocket.getInputStream()));
            
            String message;
            while ((message = peerIn.readLine()) != null) {
                textArea.append("Lena: " + message + "\n");
            }
        } catch (IOException e) {
            textArea.append("Error communicating with peer: " + e.getMessage() + "\n");
        }
    }

    @Override
    public void windowActivated(WindowEvent e) {}

    @Override
    public void windowClosed(WindowEvent e) {}

    @Override
    public void windowClosing(WindowEvent e) {
        // Close the TCP connection properly
        try {
            if (TCPSocket != null && !TCPSocket.isClosed()) {
                TCPSocket.close(); // Close the TCP socket
            }
        } catch (IOException e1) {
            e1.printStackTrace();  // Handle the exception if closing the socket fails
        }

        // Close the window and exit the application
        dispose();
        System.exit(0); // Exit the application gracefully
    }

    @Override
    public void windowDeactivated(WindowEvent e) {}

    @Override
    public void windowDeiconified(WindowEvent e) {}

    @Override
    public void windowIconified(WindowEvent e) {}

    @Override
    public void windowOpened(WindowEvent e) {}
}*/
//To change to UDP with Encryption for P2P Chat, remove the comment symbols from rows 469-693 and make comments the above from rows 22-463
//----------------------------------------------------------------------------------------------
//App_Encryption

//For encryption
/*
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class App extends Frame implements WindowListener, ActionListener {
  
  // GUI components
  static TextField ipTextField;
  static TextField inputTextField;
  static JTextArea textArea;
  static JFrame frame;
  static JButton sendButton;
  public static Color gray;
  final static String newline = "\n";

  // Networking components
  private DatagramSocket sendSocket;
  private DatagramSocket receiveSocket;
  private final int port = 12345; // Fixed port for both sending and receiving
  
  // Encryption
  //private KeyGenerator keyGenerator;
  private SecretKey key;
  private IvParameterSpec ivParameterSpec;
  private String enc_algorithm = "AES/CBC/PKCS5Padding";
  private String encrypted_message, decrypted_message;

  // Buffer size
  private final int bufferSize = 1024;

  // Construct the app's frame and initialize important parameters
  public App(String title) {

      super(title);
      gray = new Color(254, 254, 254);
      setBackground(gray);
      setLayout(new FlowLayout());
      addWindowListener(this);
      
      // chatSphere logo
      ImageIcon icon = new ImageIcon(getClass().getResource("/image/chatSphere_logo.png")); // Image path
      setIconImage(icon.getImage());

      // Setting up the TextField and the TextArea
      ipTextField = new TextField();
      ipTextField.setColumns(15);
      inputTextField = new TextField();
      inputTextField.setColumns(20);

      textArea = new JTextArea(10, 40);
      textArea.setLineWrap(true);
      textArea.setEditable(false);
      JScrollPane scrollPane = new JScrollPane(textArea);
      scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

      // Setting up the buttons
      sendButton = new JButton("Send");

      // Adding components to the GUI
      add(scrollPane);
      add(new Label("IP Address:"));
      add(ipTextField);
      add(inputTextField);
      add(sendButton);

      // Linking buttons to the ActionListener
      sendButton.addActionListener(this);

      // Initialize networking
      try {
          sendSocket = new DatagramSocket();
          receiveSocket = new DatagramSocket(port);
      } catch (SocketException e) {
          System.err.println("Error initializing sockets: " + e.getMessage());
      }

      // Encryption
      try {
          //keyGenerator = KeyGenerator.getInstance("AES");
          //keyGenerator.init(128);
    	  String keyString = "AL_CompNetworks!";
          //key = keyGenerator.generateKey();
    	  key = new SecretKeySpec(keyString.getBytes(), "AES");
    	  
    	  String ivString = "0123456789Networ"; // 16 characters (128 bits)
          ivParameterSpec = new IvParameterSpec(ivString.getBytes());

          Cipher.getInstance("AES/CBC/PKCS5Padding");
      } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
          e.printStackTrace();
          System.err.println("Error initializing encryption: " + e.getMessage());
      }

      // Start receiving messages
      new Thread(() -> {
          try {
              receiveMessages();
          } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                  | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
              e.printStackTrace();
          }
      }).start();
  }

  public static void main(String[] args) {
      App app = new App("chatSphere - AUTH (with Encryption)");
      app.setSize(500, 300);
      app.setVisible(true);
  }

  @Override
  public void actionPerformed(ActionEvent e) {
      // check which button was clicked
      if (e.getSource() == sendButton) {
          try {
              sendMessage();
          } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                  | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e1) {
              e1.printStackTrace();
          }
      }
  }

  private void sendMessage() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException { 
      String message = inputTextField.getText();
      String remoteIP = ipTextField.getText();

      if (message.isEmpty()) return;

      if (remoteIP.isEmpty()) {
          textArea.append("Error: No remote IP specified.\n");
          return;
      }
      
      try {
          // Encrypt the message
          encrypted_message = encrypt(enc_algorithm, message, key, ivParameterSpec);
          
          // Convert the Base64-encoded encrypted message to bytes
          byte[] buffer = encrypted_message.getBytes();
          
          DatagramPacket packet = new DatagramPacket(buffer, buffer.length, InetAddress.getByName(remoteIP), port);
          sendSocket.send(packet);
          
          textArea.append("Aggeliki: " + message + "\n");
          inputTextField.setText("");
      } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
      InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException ex) {
          System.err.println("Error sending message: " + ex.getMessage());
          ex.printStackTrace();
      }
  }

  private void receiveMessages() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
      byte[] buffer = new byte[bufferSize];
      
      try {
          while (true) {
              DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
              receiveSocket.receive(packet);

              String encrypted_message = new String(packet.getData(), 0, packet.getLength());
              decrypted_message = decrypt(enc_algorithm, encrypted_message, key, ivParameterSpec);

              textArea.append("Lena: " + decrypted_message + "\n");
          }
      } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
              InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException ex) {
          System.err.println("Error receiving messages: " + ex.getMessage());
      }
  }
  
  public static String encrypt(String algorithm, String input, SecretKey key,
          IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
          InvalidAlgorithmParameterException, InvalidKeyException,
          BadPaddingException, IllegalBlockSizeException {
          
          Cipher cipher = Cipher.getInstance(algorithm);
          cipher.init(Cipher.ENCRYPT_MODE, key, iv);
          byte[] cipherText = cipher.doFinal(input.getBytes());
          return Base64.getEncoder().encodeToString(cipherText);
      }
  
  public static String decrypt(String algorithm, String cipherText, SecretKey key,
          IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
          InvalidAlgorithmParameterException, InvalidKeyException,
          BadPaddingException, IllegalBlockSizeException {
          
          Cipher cipher = Cipher.getInstance(algorithm);
          cipher.init(Cipher.DECRYPT_MODE, key, iv);
          byte[] plainText = cipher.doFinal(Base64.getDecoder()
              .decode(cipherText));
          return new String(plainText);
      }

  @Override
  public void windowActivated(WindowEvent e) {}

  @Override
  public void windowClosed(WindowEvent e) {}

  @Override
  public void windowClosing(WindowEvent e) {
      dispose();
      System.exit(0);
  }

  @Override
  public void windowDeactivated(WindowEvent e) {}

  @Override
  public void windowDeiconified(WindowEvent e) {}

  @Override
  public void windowIconified(WindowEvent e) {}
  
  @Override
  public void windowOpened(WindowEvent e) {}
}
*/
