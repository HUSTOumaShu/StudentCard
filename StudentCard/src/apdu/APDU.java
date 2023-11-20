package apdu;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import tools.HexConverter;

public class APDU {
    private CommandAPDU command;
    private ResponseAPDU response;
    private Card card;
    private boolean isConnect;

    public void connect() {

        // Connect the list of cards input
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminals terminals = factory.terminals();

        // Get the first card input
        CardTerminal terminal;
        try {
            terminal = terminals.list().get(0);
            card = terminal.connect("*");
            isConnect = true;
        } catch (CardException e) {
            e.printStackTrace();
        }
    }

    public void selectApplet(CommandAPDU command) {
        this.command = command;
        try {
            this.response = this.card.getBasicChannel().transmit(this.command);

            // Get status code SW1 - SW2 from ResponseAPDU
            int sw1 = this.response.getSW1();
            int sw2 = this.response.getSW2();
            if(sw1 != 144 && sw2 != 0) {
                System.out.println(sw1);
                System.out.println("Status error code: " + Integer.toHexString(sw1)
                        + " " + Integer.toHexString(sw2));
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
    }

    public String sendData(byte CLA, byte INS, byte P1, byte P2, byte[] data, boolean isPrint) {

        // Create apdu
        byte LC = (byte)data.length;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] header = new byte[] {CLA, INS, P1, P2, LC};
        try {
            outputStream.write(header);
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.command = new CommandAPDU(outputStream.toByteArray());

        // send apdu to Card and receive response data
        try {
            this.response = this.card.getBasicChannel().transmit(this.command);
            byte[] responseData = this.response.getData();

            // Convert response data to hex string
            String str_data = new HexConverter().convert(responseData);
            if(isPrint == true) {
                System.out.println("Received data: " + str_data);
            }

            // Get status code SW1 - SW2 from ResponseAPDU
            int sw1 = this.response.getSW1();
            int sw2 = this.response.getSW2();
            if(sw1 != 144 && sw2 != 0) {
                System.out.println("Status code: " + Integer.toHexString(sw1)
                        + " " + Integer.toHexString(sw2));
            }
            return str_data;
        } catch (CardException e) {
            e.printStackTrace();
        }
        return "";
    }

    public String sendData(byte CLA, byte INS, byte P1, byte P2, String stringHex, boolean isPrint) {
        new HexConverter();
        // Convert string hex to bytes array
        byte[] data = HexConverter.hexStringToByteArray(stringHex);
        String str_data = sendData(CLA, INS, P1, P2, data, isPrint);
        return str_data;
    }

    public void disConnect() {
        try {
            this.card.disconnect(false);
        } catch (CardException e) {
            e.printStackTrace();
        }
    }

    /*
     * Getter & Setter
     */
    public CommandAPDU getCommand() {
        return command;
    }
    public void setCommand(CommandAPDU command) {
        this.command = command;
    }
    public ResponseAPDU getResponse() {
        return response;
    }
    public void setResponse(ResponseAPDU response) {
        this.response = response;
    }
    public Card getCard() {
        return card;
    }
    public void setCard(Card card) {
        this.card = card;
    }
    public boolean isConnect() {
        return isConnect;
    }
    public void setConnect(boolean isConnect) {
        this.isConnect = isConnect;
    }

}
