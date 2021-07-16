import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;


public class Server {

    public static class ElgamalPublicKey{
        public BigInteger g;
        public BigInteger p;
        public BigInteger q;
        public BigInteger y;
    }

    public static class ElgamalCipherText{
        public BigInteger c1;
        public BigInteger c2;
    }

    public static class Voter{
        public String email;
        public String name;
        public String password;
        public Vote vote;
        public String vote_hash = null;
        public String voter_id;
        public int state = 0;
    }

    public static class Question{
        public List<String> answers;
        public String question;
    }

    public static class Election{
        public ElgamalCipherText[][] tally;
        public String fingerprint;
        public String name;
        public ElgamalPublicKey pk;
        public List<Question> questions;
        public String voters_hash;
    }

    public static class VoteProof{
        public BigInteger challenge;
        public BigInteger commitA;
        public BigInteger commitB;
        public BigInteger response;
    }

    public static class EncryptedAnswer{
        public List<ElgamalCipherText> choices;
        public List<VoteProof> proofs;
        public List<VoteProof> overallProof;
    }

    public static class AuditEncryptedAnswer{
        public int answer;
        public List<ElgamalCipherText> choices;
        public List<VoteProof> proofs;
        public List<VoteProof> overallProof;
        public List<BigInteger> randomness;
    }

    public static class AuditVote{
        public List<AuditEncryptedAnswer> answers;
        public String election_fingerprint;
        public String election_id;
    }

    public static class Vote{
        public List<EncryptedAnswer> answers;
        public String election_fingerprint;
        public String election_id;
    }

    public static class CastVote{
        public Date castTime;
        public Vote vote;
        public String vote_hash;
        public String voter_hash;
        public String voter_id;
    }

    public static class Result{
        public int [][] count;
//        public VoteProof [][] proofs;
    }

    public static class KeyProof{
        public BigInteger challenge;
        public BigInteger commitment;
        public BigInteger response;
    }

    public static class Trustee{
        public String email;
        public ElgamalPublicKey epk;
        public String id;
        public KeyProof kp;
        public BigInteger [][] partialDecrypt;
        public String password;
        public VoteProof [][] proofs;
        public int state;
    }

    public static class ThreadInfo{
        public int numT1 = 0;
        public int numT2 = 0;
        public int currT = 0;
        public int doneT = 0;
        public int phase3 = 0;
        public int phase4 = 0;
    }

    private static List<Voter> voterList;
    private static List<Trustee> trusteeList;
    private static Election election;
    private static List<CastVote> castVotes;
    private static Result result;

    public static ThreadInfo tInfo;


    public static class TrusteePhaseOne extends Thread {
        protected Socket socket;
        public TrusteePhaseOne(Socket clientSocket){
            this.socket = clientSocket;
        }

        public void run(){
            DataInputStream in = null;
            DataOutputStream out = null;
            try{
                in = new DataInputStream( socket.getInputStream()  );
                out = new DataOutputStream( socket.getOutputStream() );
            } catch(IOException e){
                return;
            }
            try{
                int position = 0;
                Boolean legitUser = false;
                String id = in.readUTF();
                String password = in.readUTF();
                for(int i=0; i<trusteeList.size(); i++){
                    if( trusteeList.get(i).id.equals(id)  &&  trusteeList.get(i).password.equals(password)
                            && trusteeList.get(i).state == 0) {
                        legitUser = true;
                        position = i;
                        trusteeList.get(i).state++;
                        break;
                    }
                }
                if(!legitUser){

                    synchronized (tInfo){
                        tInfo.currT--;
                    }
                    out.writeUTF("Nevazeci kredencijali. Pokusajte ponovo.");
                    in.close();
                    out.close();
                    socket.close();
                    return;
                }

                out.writeUTF("Uspesan login.");

                synchronized (tInfo){
                    tInfo.numT1++;
                }

                out.writeUTF( election.pk.p.toString() );
                out.flush();
                out.writeUTF( election.pk.q.toString() );
                out.flush();
                out.writeUTF( election.pk.g.toString() );
                out.flush();

                BigInteger yPartial = new BigInteger( in.readUTF() );
                trusteeList.get(position).epk = new ElgamalPublicKey();
                trusteeList.get(position).epk.p = election.pk.p;
                trusteeList.get(position).epk.q = election.pk.q;
                trusteeList.get(position).epk.g = election.pk.g;
                trusteeList.get(position).epk.y = yPartial;

                synchronized (election){
                    election.pk.y = election.pk.y.multiply(yPartial);
                }

                trusteeList.get(position).kp = new KeyProof();
                trusteeList.get(position).kp.commitment = new BigInteger( in.readUTF() );
                trusteeList.get(position).kp.challenge = new BigInteger( in.readUTF() );
                trusteeList.get(position).kp.response = new BigInteger( in.readUTF() );

                if(!Operations.isKeyProofValid(
                        trusteeList.get(position).kp.commitment, trusteeList.get(position).kp.challenge, trusteeList.get(position).kp.response,
                        election.pk.p, election.pk.q, election.pk.g, yPartial)){
                    in.close();
                    out.close();
                    socket.close();
                    return;
                }


                synchronized (tInfo){
                    tInfo.numT2--;
                }

                while(tInfo.phase3 == 0)
                    Thread.sleep(1000);


                StringBuilder sb = new StringBuilder();
                for(int i=0; i<election.questions.size(); i++) {
                    for (int j = 0; j < election.questions.get(i).answers.size(); j++) {
                        sb.append( election.tally[i][j].c1.toString()+","+election.tally[i][j].c2.toString()+"," );
                    }
                }
                sb.deleteCharAt( sb.length() - 1 );

                out.writeInt(election.questions.size());
                for(int i=0; i<election.questions.size(); i++)
                    out.writeInt( election.questions.get(i).answers.size() );

                out.writeUTF( sb.toString() );

                Trustee thisTrustee = trusteeList.get(position);
                thisTrustee.partialDecrypt = new BigInteger[election.questions.size()][30];
                thisTrustee.proofs = new Server.VoteProof[election.questions.size()][30];
                for(int i=0; i<election.questions.size(); i++) {
                    for (int j = 0; j < election.questions.get(i).answers.size(); j++) {
                        thisTrustee.partialDecrypt[i][j] = new BigInteger( in.readUTF() );
                        VoteProof proof = new VoteProof();
                        proof.challenge = new BigInteger( in.readUTF() );
                        proof.commitA = new BigInteger( in.readUTF() );
                        proof.commitB = new BigInteger( in.readUTF() );
                        proof.response = new BigInteger( in.readUTF() );
                        thisTrustee.proofs[i][j] = proof;
                    }
                }

                synchronized (tInfo){
                    tInfo.doneT++;
                }

                in.close();
                out.close();
                socket.close();
            }catch (IOException | InterruptedException e) {
                e.printStackTrace();
                return;
            }
        }
    }

    public static class VoterPhaseTwo extends Thread {
        protected Socket socket;
        public VoterPhaseTwo(Socket clientSocket){
            this.socket = clientSocket;
        }

        public void run() {
            DataInputStream in = null;
            DataOutputStream out = null;
            try{
                in = new DataInputStream( socket.getInputStream()  );
                out = new DataOutputStream( socket.getOutputStream() );
            } catch(IOException e){
                return;
            }
            try {
                int position = 0;
                Boolean legitUser = false;
                String id = in.readUTF();
                String password = in.readUTF();
                for(int i=0; i<voterList.size(); i++){
                    if( voterList.get(i).voter_id.equals(id)  &&  voterList.get(i).password.equals(password)
                            && voterList.get(i).state == 0) {
                        legitUser = true;
                        position = i;
                        voterList.get(i).state++;
                        break;
                    }
                }
                if(!legitUser){

                    out.writeUTF("Nevazeci kredencijali. Pokusajte ponovo.");
                    in.close();
                    out.close();
                    socket.close();
                    return;
                }

                out.writeUTF( election.fingerprint );

                out.writeUTF( election.pk.p.toString() );
                out.flush();
                out.writeUTF( election.pk.q.toString() );
                out.flush();
                out.writeUTF( election.pk.g.toString() );
                out.flush();
                out.writeUTF( election.pk.y.toString() );
                out.flush();

                out.writeUTF( election.name );
                out.flush();
                out.writeInt( election.questions.size() );
                out.flush();
                for(int i=0; i<election.questions.size(); i++){
                    Question current = election.questions.get(i);
                    out.writeUTF( current.question );
                    out.flush();
                    out.writeUTF( String.join(",", current.answers) );
                    out.flush();
                }

                String voteString = in.readUTF();
                if(voteString.equals("Audit")){
                    in.close();
                    out.close();
                    socket.close();
                    return;
                }

                String[] v = voteString.split(",");
                Vote vote = new Vote();
                vote.election_fingerprint = v[0];
                vote.answers = new ArrayList<>();
                int pos = 1;
                for(int i=0; i<election.questions.size(); i++){
                    EncryptedAnswer answer = new EncryptedAnswer();
                    answer.choices = new ArrayList<>();
                    answer.overallProof = new ArrayList<>();
                    answer.proofs = new ArrayList<>();
                    int numC = election.questions.get(i).answers.size();
                    for(int j=0; j<numC; j++){
                        ElgamalCipherText ect = new ElgamalCipherText();
                        ect.c1 = new BigInteger( v[pos++] );
                        ect.c2 = new BigInteger( v[pos++] );
                        answer.choices.add(ect);
                    }
                    for(int j=0; j<2; j++){
                        VoteProof proof = new VoteProof();
                        proof.challenge = new BigInteger( v[pos++] );
                        proof.commitA = new BigInteger( v[pos++] );
                        proof.commitB = new BigInteger( v[pos++] );
                        proof.response = new BigInteger( v[pos++] );
                        answer.overallProof.add(proof);
                    }
                    for(int j=0; j<numC*2; j++){
                        VoteProof proof = new VoteProof();
                        proof.challenge = new BigInteger( v[pos++] );
                        proof.commitA = new BigInteger( v[pos++] );
                        proof.commitB = new BigInteger( v[pos++] );
                        proof.response = new BigInteger( v[pos++] );
                        answer.proofs.add(proof);
                    }
                    vote.answers.add(answer);
                }

                if( !Operations.verifyVote(election.fingerprint, vote, election.pk) ){
                    in.close();
                    out.close();
                    socket.close();
                    return;
                }

                Voter thisVoter = voterList.get(position);
                CastVote castVote = new CastVote();
                castVote.castTime = new Date();
                castVote.voter_id = thisVoter.voter_id;
                castVote.vote = vote;
                castVote.vote_hash = Operations.getVoteHash(vote);
                castVote.voter_hash = Operations.getOneVoterHash(thisVoter);

                for(int i=0; i<castVotes.size(); i++){
                    if(castVotes.get(i).voter_id.equals( castVote.voter_id )){
                        synchronized (castVotes){
                            castVotes.remove(i);
                        }
                        break;
                    }
                }
                synchronized (castVotes) {
                    castVotes.add(castVote);
                }


                while(tInfo.phase4 == 0)
                    Thread.sleep(1000);


                int numq = election.questions.size();
                int[] numc = new int [numq];
                for(int i=0; i<numq; i++)
                    numc[i] = election.questions.get(i).answers.size();

                StringBuilder sb = new StringBuilder();
                for(int i=0; i<numq; i++)
                    for(int j=0; j<numc[i]; j++){
                        sb.append(election.tally[i][j].c1+","+election.tally[i][j].c2+",");
                    }
                sb.deleteCharAt( sb.length() - 1 );
                out.writeUTF( sb.toString() );

                sb = new StringBuilder();
                sb.append( election.pk.p+","+election.pk.q+","+election.pk.g+","+election.pk.y+","+election.fingerprint+","+election.voters_hash);
                out.writeUTF( sb.toString() );

                out.writeInt( voterList.size() );
                for(int i=0; i<voterList.size(); i++){
                    Voter current = voterList.get(i);
                    sb = new StringBuilder();
                    sb.append( current.voter_id+","+current.password+","+current.email+","+current.name);
                    out.writeUTF( sb.toString() );
                }

                sb = new StringBuilder();
                for(int i=0; i<numq; i++)
                    for(int j=0; j<numc[i]; j++){
                        sb.append(result.count[i][j]+",");
                    }
                sb.deleteCharAt( sb.length() - 1 );
                out.writeUTF( sb.toString() );


                out.writeInt( castVotes.size() );
                for(int k=0; k<castVotes.size(); k++){
                    CastVote cv = castVotes.get(k);
                    sb = new StringBuilder();
                    sb.append( cv.castTime.toString()+","+cv.vote_hash+","+cv.voter_hash+","+cv.voter_id+","+cv.vote.election_fingerprint);
                    out.writeUTF( sb.toString() );

                    for(int i=0; i<numq; i++){
                        EncryptedAnswer answer = cv.vote.answers.get(i);
                        sb = new StringBuilder();
                        for(int j=0; j<numc[i]; j++){
                            sb.append( answer.choices.get(j).c1+","+answer.choices.get(j).c2+",");
                        }
                        sb.deleteCharAt( sb.length() - 1 );
                        out.writeUTF( sb.toString() );

                        sb = new StringBuilder();
                        for(int j=0; j<numc[i]*2; j++){
                            sb.append( answer.proofs.get(j).challenge+","
                                    +answer.proofs.get(j).commitA+","+
                                    answer.proofs.get(j).commitB+","+answer.proofs.get(j).response+",");
                        }
                        sb.deleteCharAt( sb.length() - 1 );
                        out.writeUTF( sb.toString() );

                        sb = new StringBuilder();
                        for(int j=0; j<2; j++){
                            sb.append( answer.overallProof.get(j).challenge+","+
                                    answer.overallProof.get(j).commitA+","+
                                    answer.overallProof.get(j).commitB+","+
                                    answer.overallProof.get(j).response+",");
                        }
                        sb.deleteCharAt( sb.length() - 1 );
                        out.writeUTF( sb.toString() );

                    }

                }

                out.writeInt( trusteeList.size() );
                for(int k=0; k<trusteeList.size(); k++){
                    Trustee trustee = trusteeList.get(k);
                    sb = new StringBuilder();
                    sb.append( trustee.id+","+trustee.password+","+
                            trustee.epk.p+","+trustee.epk.q+","+trustee.epk.g+","+trustee.epk.y+","+
                            trustee.kp.challenge+","+trustee.kp.commitment+","+trustee.kp.response);
                    out.writeUTF( sb.toString() );

                    sb = new StringBuilder();
                    for(int i=0; i<numq; i++)
                        for(int j=0; j<numc[i]; j++){
                            sb.append( trustee.partialDecrypt[i][j]+"," );
                        }
                    sb.deleteCharAt( sb.length() - 1 );
                    out.writeUTF( sb.toString() );

                    sb = new StringBuilder();
                    for(int i=0; i<numq; i++)
                        for(int j=0; j<numc[i]; j++){
                            sb.append( trustee.proofs[i][j].challenge+","+trustee.proofs[i][j].commitA+","+
                                    trustee.proofs[i][j].commitB+","+trustee.proofs[i][j].response+",");
                        }
                    sb.deleteCharAt( sb.length() - 1 );
                    out.writeUTF( sb.toString() );
                }


                voterList.get(position).state--;

                in.close();
                out.close();
                socket.close();
            }catch (IOException | InterruptedException e) {
                e.printStackTrace();
                return;
            }
        }
    }

    public static void main(String[] args){
        try {
            //////////////////////
            final char[] password = "lozinka".toCharArray();
            final int LISTENING_PORT = 443;

            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream("C:/sert/keystore.jks"), password);

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("NewSunX509");
            keyManagerFactory.init(keyStore, password);

            final SSLContext context = SSLContext.getInstance("SSL");//"SSL" "TLS"
            context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            final SSLServerSocketFactory factory = context.getServerSocketFactory();
            SSLServerSocket socket = ((SSLServerSocket) factory.createServerSocket(LISTENING_PORT));

            Socket client = null;
            ///////////////////////
            election = new Election();
            election.pk = new ElgamalPublicKey();
            election.pk.p = Operations.preparedP();
            election.pk.q = election.pk.p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
            election.pk.g = Operations.preparedG2();
            election.pk.y = BigInteger.ONE;

            castVotes = new ArrayList<>();

            election.questions = new ArrayList<>();
            File file = new File("Questions.txt");
            Scanner myReader = new Scanner(file);
            election.name = myReader.nextLine();
            while(myReader.hasNextLine()){
                Question q = new Question();
                q.question = myReader.nextLine();
                if(!myReader.hasNextLine())
                    break;
                String answers = myReader.nextLine();
                q.answers = new ArrayList<>( Arrays.asList( answers.split(",") ) );
                election.questions.add(q);
            }
            myReader.close();

            trusteeList = new ArrayList<>();
            file = new File("Trustees.txt");
            myReader = new Scanner(file);
            while(myReader.hasNextLine()){
                String id = myReader.nextLine();
                if(!myReader.hasNextLine())
                    break;
                String pass = myReader.nextLine();

                Trustee t = new Trustee();
                t.id = id;
                t.password = pass;
                t.state = 0;
                trusteeList.add(t);
            }
            myReader.close();

            voterList = new ArrayList<>();
            file = new File("Voters.txt");
            myReader = new Scanner(file);
            while(myReader.hasNextLine()){
                String id = myReader.nextLine();
                if(!myReader.hasNextLine())
                    break;
                String pass = myReader.nextLine();
                if(!myReader.hasNextLine())
                    break;
                String email = myReader.nextLine();
                if(!myReader.hasNextLine())
                    break;
                String name = myReader.nextLine();

                Voter v = new Voter();
                v.voter_id = id;
                v.password = pass;
                v.email = email;
                v.name = name;
                v.state = 0;
                voterList.add(v);
            }
            myReader.close();

            election.voters_hash = Operations.getVoterHash(voterList);

            tInfo = new ThreadInfo();
            tInfo.numT1 = 0;
            tInfo.numT2 = trusteeList.size();
            tInfo.currT = 0;
            tInfo.doneT = 0;
            tInfo.phase3 = 0;
            tInfo.phase4 = 0;

             while (tInfo.numT1 < trusteeList.size()){
                 Thread.sleep(500);
                 if(tInfo.currT < trusteeList.size()) {
                     try {
                         client = socket.accept();
                     } catch (IOException e) {
                         e.printStackTrace();
                     }
                     new TrusteePhaseOne(client).start();
                     tInfo.currT++;
                 }
             }

             while(tInfo.numT2 > 0) {
                 Thread.sleep(1000);
             }

             System.out.println("Prva faza gotova!");


             election.fingerprint = Operations.getElectionFingerprint(election);

            final long voteDurationInMinutes = 3;
            final long minuteInMillis = 60000;
            Calendar date = Calendar.getInstance();
            long t = date.getTimeInMillis();
            Date endOfVote = new Date( t + voteDurationInMinutes * minuteInMillis );
            Date current = null;

            while( (current = new Date()).before(endOfVote) ){

                socket.setSoTimeout( (int)(endOfVote.getTime() - current.getTime()) );
                try{
                    client = socket.accept();
                }catch (IOException e) {
                    break;
                }
                new VoterPhaseTwo(client).start();
            }

            election.tally = new ElgamalCipherText[ election.questions.size() ][30];
            for(int i=0; i<election.questions.size(); i++){
                Question currq = election.questions.get(i);

                for(int j=0; j<currq.answers.size(); j++){
                    ElgamalCipherText sum = new ElgamalCipherText();
                    sum.c1 = BigInteger.ONE;
                    sum.c2 = BigInteger.ONE;

                    for(CastVote cv: castVotes){
                        ElgamalCipherText ect = cv.vote.answers.get(i).choices.get(j);
                        sum = Operations.homomorphic_add(sum, ect, election.pk);
                    }
                    election.tally[i][j] = sum;
                }
            }

            System.out.println("Druga faza gotova!");

            tInfo.phase3 = 1;

            while(tInfo.doneT < trusteeList.size())
                Thread.sleep(1000);

            result = new Result();
            result.count = new int [election.questions.size()][30];
            for(int i=0; i<election.questions.size(); i++) {
                System.out.println("Za pitanje: "+ election.questions.get(i).question);
                System.out.println("Rezultati su: ");
                for (int j = 0; j < election.questions.get(i).answers.size(); j++) {
                    BigInteger product = BigInteger.ONE;
                    for (Trustee trustee : trusteeList) {
                        product = product.multiply(trustee.partialDecrypt[i][j]).mod(election.pk.p);
                        if (!Operations.isDecryptionProofValid(trustee.proofs[i][j], trustee.epk, election.tally[i][j], trustee.partialDecrypt[i][j])) {
                            System.out.println("Jedan od dokaza dekripcije nije validan, ponistavaju se izbori.");
                            socket.close();
                            return;
                        }


                    }
                    BigInteger temp = product.modInverse(election.pk.p).multiply(election.tally[i][j].c2).mod(election.pk.p);
                    result.count[i][j] = (temp.bitLength() -1) / (election.pk.g.bitLength() - 1 );
                    System.out.print(election.questions.get(i).answers.get(j)+": ");
                    System.out.print(result.count[i][j] + " ");
                }
                System.out.println();
            }

            tInfo.phase4 = 1;

            System.out.println("Kada ste spremni da zavrsite fazu revizije, pritisnite bilo koji taster.");
            int end = System.in.read();

        socket.close();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyManagementException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
