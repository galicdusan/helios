import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class Trustee {

    public static class SecretKey {
        public Server.ElgamalPublicKey epk;
        public BigInteger secretKey;

        public SecretKey(){}
    }

    public static class Info{
        public String email;
        public String id;
        public Server.KeyProof kp;
        public BigInteger[][] partialDecrypt;
        public String password;
        public Server.VoteProof[][] proofs;
        public SecretKey secretKey;
    }

    public static void main(String[] args){
        try {
            //////////////////////////////////////
            final char[] password = "lozinka".toCharArray();

            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream("C:/sert/keystore.jks"), password);

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("NewSunX509");
            keyManagerFactory.init(keyStore, password);

            final SSLContext context = SSLContext.getInstance("SSL");//"SSL" "TLS"
            context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            SSLSocketFactory sf = context.getSocketFactory();

            ////////////////////////////////////
            Thread.sleep(500);
            SSLSocket client = (SSLSocket) sf.createSocket("localhost", 443);
            DataInputStream in = new DataInputStream( client.getInputStream() );
            DataOutputStream out = new DataOutputStream( client.getOutputStream() );

            Info myInfo = new Info();
            Scanner scanner = new Scanner(System.in);
            System.out.println("Unesite id:");
            myInfo.id = scanner.next();
            System.out.println("Unesite lozinku:");
            myInfo.password = scanner.next();

            out.writeUTF(myInfo.id);
            out.flush();
            out.writeUTF(myInfo.password);
            out.flush();

            String statusMsg = in.readUTF();
            if(statusMsg.equals("Nevazeci kredencijali. Pokusajte ponovo."))
            {
                in.close();
                out.close();
                client.close();
                return;
            }

            BigInteger p = new BigInteger( in.readUTF() );
            BigInteger q = new BigInteger( in.readUTF() );
            BigInteger g = new BigInteger( in.readUTF() );
            myInfo.secretKey = Operations.createPublicKeyPair(p,q,g);

            out.writeUTF( myInfo.secretKey.epk.y.toString() );
            out.flush();

            myInfo.kp = Operations.createKeyProof(p,q,g,myInfo.secretKey.secretKey, myInfo.secretKey.epk.y);
            out.writeUTF(myInfo.kp.commitment.toString());
            out.flush();
            out.writeUTF(myInfo.kp.challenge.toString());
            out.flush();
            out.writeUTF(myInfo.kp.response.toString());
            out.flush();

            int numq = in.readInt();
            int[] numc = new int [numq];
            for(int i=0; i<numq; i++)
                numc[i] = in.readInt();

            Server.ElgamalCipherText[][] tally = new Server.ElgamalCipherText[numq][30];
            String tallyString = in.readUTF();
            String[] t = tallyString.split(",");
            int pos = 0;
            for(int i=0; i<numq; i++){
                for(int j=0; j<numc[i]; j++){
                    Server.ElgamalCipherText ect = new Server.ElgamalCipherText();
                    ect.c1 = new BigInteger( t[pos++] );
                    ect.c2 = new BigInteger( t[pos++] );
                    tally[i][j] = ect;
                }
            }

            myInfo.partialDecrypt = new BigInteger[numq][30];
            myInfo.proofs = new Server.VoteProof[numq][30];
            for(int i=0; i<numq; i++)
                for(int j=0; j<numc[i]; j++) {
                    myInfo.partialDecrypt[i][j] = tally[i][j].c1.modPow(myInfo.secretKey.secretKey, myInfo.secretKey.epk.p);
                    myInfo.proofs[i][j] = Operations.getDecryptionProof(myInfo.secretKey.epk, tally[i][j], myInfo.secretKey);

                    out.writeUTF( myInfo.partialDecrypt[i][j].toString() );
                    out.writeUTF( myInfo.proofs[i][j].challenge.toString() );
                    out.writeUTF( myInfo.proofs[i][j].commitA.toString() );
                    out.writeUTF( myInfo.proofs[i][j].commitB.toString() );
                    out.writeUTF( myInfo.proofs[i][j].response.toString() );
                }



            in.close();
            out.close();
            client.close();
        } catch (IOException | InterruptedException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyManagementException e) {
            e.printStackTrace();
        }
    }
}
