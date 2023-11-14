package apdu;

import javax.smartcardio.CommandAPDU;

public class List_of_apdus {

    /*
     * List of Applets
     */
    private CommandAPDU service_sendData = new CommandAPDU(new byte[] {0x00,
            (byte) 0xA4, 0x04, 0x00, 0x06,
            (byte) 0x01, 0x20, 0x20, 0x47, 0x57, 0x01});
    private CommandAPDU service_cryptoData = new CommandAPDU(new byte[] {0x00,
            (byte) 0xA4, 0x04, 0x00, 0x06,
            (byte) 0x01, 0x20, 0x20, 0x47, 0x57, 0x02});
    private CommandAPDU service_genRandom = new CommandAPDU(new byte[] {0x00,
            (byte) 0xA4, 0x04, 0x00, 0x06,
            (byte) 0x01, 0x20, 0x20, 0x47, 0x57, 0x03});
    private CommandAPDU service_rsaSignature = new CommandAPDU(new byte[] {0x00,
            (byte) 0xA4, 0x04, 0x00, 0x06,
            (byte) 0x01, 0x20, 0x20, 0x47, 0x57, 0x04});
    private CommandAPDU service_hash = new CommandAPDU( new byte[] {0x00,
            (byte) 0xA4, 0x04, 0x00, 0x06,
            (byte) 0x01, 0x20, 0x20, 0x47, 0x57, 0x05});
    private CommandAPDU service_verify = new CommandAPDU( new byte[] {0x00,
            (byte) 0xA4, 0x04, 0x00, 0x06,
            (byte) 0x01, 0x20, 0x20, 0x47, 0x57, 0x06});

    /*
     * TGP System
     */
    private CommandAPDU tgp_system = new CommandAPDU(new byte[] {0x00,
            (byte)0xA4, 0x04, 0x00, 0x06,
            (byte)0x00, 0x20, 0x20, 0x47, 0x57, 0x01});
    private CommandAPDU tgp_server1 = new CommandAPDU(new byte[] {0x00,
            (byte)0xA4, 0x04, 0x00, 0x06,
            (byte)0x40, 0x20, 0x20, 0x47, 0x57, 0x01});

    /*
     * CSR Generation System
     */
    private CommandAPDU csr_system = new CommandAPDU(new byte[] {0x00,
            (byte)0xA4, 0x04, 0x00, 0x06,
            (byte)0x20, 0x20, 0x47, 0x57, 0x01, 0x01});

    /*
     * Other services
     */
    // IAC System

    // Sender only contain data needed to share
    private CommandAPDU iac_sender = new CommandAPDU(new byte[] {0x00,
            (byte)0xA4, 0x04, 0x00, 0x06,
            (byte)0x20, 0x20, 0x20, 0x47, 0x57, 0x01});
    // Receiver call apdu to get the data
    private CommandAPDU iac_receiver = new CommandAPDU(new byte[] {0x00,
            (byte)0xA4, 0x04, 0x00, 0x06,
            (byte)0x30, 0x20, 0x20, 0x47, 0x57, 0x01});

    /*
     * Getter & Setter
     */
    public CommandAPDU getService_sendData() {
        return service_sendData;
    }
    public void setService_sendData(CommandAPDU service_sendData) {
        this.service_sendData = service_sendData;
    }
    public CommandAPDU getService_cryptoData() {
        return service_cryptoData;
    }
    public void setService_cryptoData(CommandAPDU service_cryptoData) {
        this.service_cryptoData = service_cryptoData;
    }
    public CommandAPDU getService_genRandom() {
        return service_genRandom;
    }
    public void setService_genRandom(CommandAPDU service_genRandom) {
        this.service_genRandom = service_genRandom;
    }
    public CommandAPDU getService_rsaSignature() {
        return service_rsaSignature;
    }
    public void setService_rsaSignature(CommandAPDU service_rsaSignature) {
        this.service_rsaSignature = service_rsaSignature;
    }
    public CommandAPDU getTgp_system() {
        return tgp_system;
    }
    public void setTgp_system(CommandAPDU tgp_system) {
        this.tgp_system = tgp_system;
    }
    public CommandAPDU getTgp_server1() {
        return tgp_server1;
    }
    public void setTgp_server1(CommandAPDU tgp_server1) {
        this.tgp_server1 = tgp_server1;
    }
    public CommandAPDU getService_hash() {
        return service_hash;
    }
    public void setService_hash(CommandAPDU service_hash) {
        this.service_hash = service_hash;
    }
    public CommandAPDU getService_verify() {
        return service_verify;
    }
    public void setService_verify(CommandAPDU service_verify) {
        this.service_verify = service_verify;
    }
    public CommandAPDU getIac_sender() {
        return iac_sender;
    }
    public void setIac_sender(CommandAPDU iac_sender) {
        this.iac_sender = iac_sender;
    }
    public CommandAPDU getIac_receiver() {
        return iac_receiver;
    }
    public void setIac_receiver(CommandAPDU iac_receiver) {
        this.iac_receiver = iac_receiver;
    }
    public CommandAPDU getCsr_system() {
        return csr_system;
    }
    public void setCsr_system(CommandAPDU csr_system) {
        this.csr_system = csr_system;
    }

}
