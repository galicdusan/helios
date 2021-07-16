import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;


public class Voter {

    public static class Info{
        public String email;
        public String name;
        public String password;
        public Server.Vote vote;
        public String vote_hash = null;
        public String voter_id;
    }

    public static class AuditInfo{
        public Server.Election election;
        public List<Server.Voter> voterList;
        public List<Server.CastVote> castVotes;
        public Server.Result result;
        public List<Server.Trustee> trusteeList;
    }

    public static void main(String[] args){
        try {
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
            myInfo.voter_id = scanner.next();
            System.out.println("Unesite lozinku:");
            myInfo.password = scanner.next();

            out.writeUTF(myInfo.voter_id);
            out.flush();
            out.writeUTF(myInfo.password);
            out.flush();

            String fingerprint = in.readUTF();
            if(fingerprint.equals("Nevazeci kredencijali. Pokusajte ponovo."))
            {
                in.close();
                out.close();
                client.close();
                return;
            }

            Server.ElgamalPublicKey pk = new Server.ElgamalPublicKey();
            pk.p = new BigInteger( in.readUTF() );
            pk.q = new BigInteger( in.readUTF() );
            pk.g = new BigInteger( in.readUTF() );
            pk.y = new BigInteger( in.readUTF() );

            String electionName = in.readUTF();
            List<Server.Question> questionList = new ArrayList<>();
            int qNum = in.readInt();
            for(int i=0; i<qNum; i++){
                Server.Question q = new Server.Question();
                q.question = in.readUTF();
                String answers = in.readUTF();
                q.answers = new ArrayList<>( Arrays.asList( answers.split(",") ) );
                questionList.add(q);
            }

            System.out.println("\nNaslov izbora: "+electionName+"\n");
            for(int i=0; i<questionList.size(); i++){
                Server.Question current = questionList.get(i);
                System.out.println(current.question+"\n");
                for(int j=0; j<current.answers.size(); j++)
                    System.out.print(current.answers.get(j)+"   ");
                System.out.println("\n");
            }
            System.out.println("Za svako pitanje upisite redni broj izbora i pritisnite Enter.");
            int [] userChoices = new int[20];
            for(int i=0; i<qNum; i++)
                userChoices[i] = scanner.nextInt();

            Server.Vote vote = new Server.Vote();
            Server.AuditVote auditVote = new Server.AuditVote();
            vote.election_fingerprint = fingerprint;
            vote.answers = new ArrayList<>();
            auditVote.election_fingerprint = fingerprint;
            auditVote.answers = new ArrayList<>();

            BigInteger one = pk.g.pow( 1 );
            BigInteger zero = pk.g.pow( 0 );
            for(int i=0; i<qNum; i++){
                Server.Question current = questionList.get(i);
                Server.EncryptedAnswer encAns = new Server.EncryptedAnswer();
                encAns.choices = new ArrayList<>();
                encAns.proofs = new ArrayList<>();
                encAns.overallProof = new ArrayList<>();
                Server.AuditEncryptedAnswer auditAns = new Server.AuditEncryptedAnswer();
                auditAns.randomness = new ArrayList<>();
                auditAns.answer = userChoices[i];

                Server.ElgamalCipherText sum = new Server.ElgamalCipherText();
                sum.c1 = BigInteger.ONE;
                sum.c2 = BigInteger.ONE;

                for(int j=0; j<current.answers.size(); j++){

                    SecureRandom random = new SecureRandom();
                    BigInteger randomness = new BigInteger(pk.q.bitLength(), random).mod(pk.q);
                    BigInteger m = null;
                    Server.ElgamalCipherText ect = null;
                    if(j+1 == userChoices[i]){
                        ect = Operations.encrypt_with_pk(pk, one, randomness);
                        m = one;
                    }
                    else{
                        ect = Operations.encrypt_with_pk(pk, zero, randomness);
                        m = zero;
                    }
                    encAns.choices.add(ect);
                    auditAns.randomness.add(randomness);
                    Operations.prepareProofs(encAns.proofs, pk, ect, m, randomness);
                    sum = Operations.homomorphic_add(sum, ect, pk);

                }

                BigInteger overall_r = BigInteger.valueOf(0);
                for(int j=0; j<auditAns.randomness.size(); j++){
                    overall_r = overall_r.add( auditAns.randomness.get(j) );
                }

                BigInteger valid = null;
                if( userChoices[i] > 0 && userChoices[i] <= current.answers.size() )
                    valid = one;
                else
                    valid = zero;
                Operations.prepareProofs(encAns.overallProof, pk, sum, valid, overall_r);

                auditAns.choices = new ArrayList<>( encAns.choices );
                auditAns.proofs = new ArrayList<>( encAns.proofs );
                auditAns.overallProof = new ArrayList<>( encAns.overallProof );


                vote.answers.add( encAns );
                auditVote.answers.add( auditAns );
            }

            String vote_hash = Operations.getVoteHash(vote);
            System.out.println( "Vas ballot tracker je: "+vote_hash );
            System.out.println( "Zapisite ga ili printscreen-ujte ga da biste mogli da pronadjete svoj glas u bazi glasova.");
            System.out.println( "Ako ste spremni da posaljete glas, pritisnite taster 1. "+
                    "Ako biste ipak da proverite da li je glas ispravno zaveden, pritisnite taster 2. "+
                    "(Ovo ce unistiti glas i moracete ponovo da popunite glas)");
            int choice = scanner.nextInt();
            if(choice == 1){
                auditVote = null;
                myInfo.vote = vote;
                myInfo.vote_hash = vote_hash;

                StringBuilder sb = new StringBuilder();
                sb.append( vote.election_fingerprint+"," );
                for(Server.EncryptedAnswer answer: vote.answers){
                    for(Server.ElgamalCipherText ect: answer.choices)
                        sb.append(ect.c1.toString()+","+ect.c2.toString()+",");
                    for(Server.VoteProof proof: answer.overallProof)
                        sb.append(proof.challenge.toString()+","+proof.commitA+","+proof.commitB+","+proof.response.toString()+",");
                    for(Server.VoteProof proof: answer.proofs)
                        sb.append(proof.challenge.toString()+","+proof.commitA+","+proof.commitB+","+proof.response.toString()+",");
                }
                sb.deleteCharAt( sb.length() - 1 );

                out.writeUTF( sb.toString() );

            } else {
                if(Operations.auditBallot(fingerprint, vote_hash, auditVote, vote, pk))
                    System.out.println( "Da, glas je korektno formiran." );
                else
                    System.out.println( "Ne, glas nije korektno formiran." );
                out.writeUTF("Audit");
                vote = null;
                auditVote = null;
                in.close();
                out.close();
                client.close();
                return;
            }


            int numq = qNum;
            int[] numc = new int[qNum];
            for(int i=0; i<qNum; i++)
                numc[i] = questionList.get(i).answers.size();

            AuditInfo auditInfo = new AuditInfo();
            auditInfo.election = new Server.Election();
            auditInfo.result = new Server.Result();
            auditInfo.election.tally = new Server.ElgamalCipherText[numq][30];
            auditInfo.election.pk = new Server.ElgamalPublicKey();

            auditInfo.voterList = new ArrayList<>();
            auditInfo.result.count = new int[numq][30];
            auditInfo.castVotes = new ArrayList<>();
            auditInfo.trusteeList = new ArrayList<>();

            auditInfo.election.questions = questionList;
            auditInfo.election.name = electionName;

            String tallyString = in.readUTF();
            String[] t = tallyString.split(",");
            int pos = 0;
            for(int i=0; i<numq; i++)
                for(int j=0; j<numc[i]; j++) {
                    auditInfo.election.tally[i][j] = new Server.ElgamalCipherText();
                    auditInfo.election.tally[i][j].c1 = new BigInteger( t[pos++] );
                    auditInfo.election.tally[i][j].c2 = new BigInteger( t[pos++] );
                }
            String eleString = in.readUTF();
            t = eleString.split(",");
            pos = 0;
            auditInfo.election.pk.p = new BigInteger( t[pos++] );
            auditInfo.election.pk.q = new BigInteger( t[pos++] );
            auditInfo.election.pk.g = new BigInteger( t[pos++] );
            auditInfo.election.pk.y = new BigInteger( t[pos++] );
            auditInfo.election.fingerprint =  t[pos++] ;
            auditInfo.election.voters_hash =  t[pos++] ;

            int numVoters = in.readInt();
            for(int i=0; i<numVoters; i++){
                String voterString = in.readUTF();
                t = voterString.split(",");
                pos = 0;
                Server.Voter voter = new Server.Voter();
                voter.voter_id = t[pos++];
                voter.password = t[pos++];
                voter.email = t[pos++];
                voter.name = t[pos++];
                auditInfo.voterList.add(voter);
            }

            String resultString = in.readUTF();
            t = resultString.split(",");
            pos = 0;
            for(int i=0; i<numq; i++)
                for(int j=0; j<numc[i]; j++){
                    auditInfo.result.count[i][j] = Integer.parseInt(t[pos++]);
                }

            SimpleDateFormat formatter = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy");

            int numCV = in.readInt();
            for(int k=0; k<numCV; k++){
                Server.CastVote castVote = new Server.CastVote();
                String voteInfo = in.readUTF();
                t = voteInfo.split(",");
                pos=0;
                castVote.castTime = formatter.parse( t[pos++] );
                castVote.vote_hash = t[pos++];
                castVote.voter_hash = t[pos++];
                castVote.voter_id = t[pos++];
                Server.Vote vt = new Server.Vote();
                vt.answers = new ArrayList<>();
                vt.election_fingerprint = t[pos++];

                for(int i=0; i<numq; i++){
                    Server.EncryptedAnswer answer = new Server.EncryptedAnswer();
                    answer.choices = new ArrayList<>();
                    answer.proofs = new ArrayList<>();
                    answer.overallProof = new ArrayList<>();

                    String choiceString = in.readUTF();
                    t = choiceString.split(",");
                    pos=0;
                    for(int j=0; j<numc[i]; j++){
                        Server.ElgamalCipherText ect = new Server.ElgamalCipherText();
                        ect.c1 = new BigInteger( t[pos++] );
                        ect.c2 = new BigInteger( t[pos++] );
                        answer.choices.add(ect);
                    }

                    String proofString = in.readUTF();
                    t = proofString.split(",");
                    pos=0;
                    for(int j=0; j<numc[i]*2; j++){
                        Server.VoteProof proof = new Server.VoteProof();
                        proof.challenge = new BigInteger( t[pos++] );
                        proof.commitA = new BigInteger( t[pos++] );
                        proof.commitB = new BigInteger( t[pos++] );
                        proof.response = new BigInteger( t[pos++] );
                        answer.proofs.add(proof);
                    }

                    String overallString = in.readUTF();
                    t = overallString.split(",");
                    pos=0;
                    for(int j=0; j<2; j++){
                        Server.VoteProof proof = new Server.VoteProof();
                        proof.challenge = new BigInteger( t[pos++] );
                        proof.commitA = new BigInteger( t[pos++] );
                        proof.commitB = new BigInteger( t[pos++] );
                        proof.response = new BigInteger( t[pos++] );
                        answer.overallProof.add(proof);
                    }

                    vt.answers.add(answer);
                }
                castVote.vote = vt;
                auditInfo.castVotes.add(castVote);
            }

            int numT = in.readInt();
            for(int k=0; k<numT; k++){
                Server.Trustee trustee = new Server.Trustee();
                trustee.epk = new Server.ElgamalPublicKey();
                trustee.kp = new Server.KeyProof();
                trustee.partialDecrypt = new BigInteger[numq][30];
                trustee.proofs = new Server.VoteProof[numq][30];

                String trusteeInfo = in.readUTF();
                t = trusteeInfo.split(",");
                pos = 0;
                trustee.id = t[pos++];
                trustee.password = t[pos++];
                trustee.epk.p = new BigInteger( t[pos++] );
                trustee.epk.q = new BigInteger( t[pos++] );
                trustee.epk.g = new BigInteger( t[pos++] );
                trustee.epk.y = new BigInteger( t[pos++] );
                trustee.kp.challenge = new BigInteger( t[pos++] );
                trustee.kp.commitment = new BigInteger( t[pos++] );
                trustee.kp.response = new BigInteger( t[pos++] );

                String decryptString = in.readUTF();
                t = decryptString.split(",");
                pos=0;
                for(int i=0; i<numq; i++)
                    for(int j=0; j<numc[i]; j++){
                        trustee.partialDecrypt[i][j] = new BigInteger( t[pos++] );
                    }

                String proofString = in.readUTF();
                t = proofString.split(",");
                pos=0;
                for(int i=0; i<numq; i++)
                    for(int j=0; j<numc[i]; j++){
                        trustee.proofs[i][j] = new Server.VoteProof();
                        trustee.proofs[i][j].challenge = new BigInteger( t[pos++] );
                        trustee.proofs[i][j].commitA = new BigInteger( t[pos++] );
                        trustee.proofs[i][j].commitB = new BigInteger( t[pos++] );
                        trustee.proofs[i][j].response = new BigInteger( t[pos++] );
                }


                auditInfo.trusteeList.add(trustee);
            }

            System.out.println("Glasanje je gotovo i svi podaci o glasanju su preuzeti. Unesite broj za prikaz/akciju:");
            System.out.println("Taster 1 za globalne parametre izbora (fingerprint, javni kljuc, enkriptovane sume itd.)");
            System.out.println("Taster 2 za listu glasaca.");
            System.out.println("Taster 3 za konacne rezultate izbora.");
            System.out.println("Taster 4 za listu ubacenih glasova.");
            System.out.println("Taster 5 za listu poverenika.");
            System.out.println("Taster 6 za proveru da li je moj glas uracunat.");
            System.out.println("Taster 7 za proveru da li su glasovi ispravno sabrani.");
            System.out.println("Taster 0 za prekid programa.");
            while(true){
                int choose = scanner.nextInt();
                switch(choose){
                    case 1:
                        Operations.printElection(auditInfo.election, numq, numc);
                        break;
                    case 2:
                        Operations.printVoterList(auditInfo.voterList, numq, numc);
                        break;
                    case 3:
                        Operations.printResult(auditInfo.result, numq, numc);
                        break;
                    case 4:
                        Operations.printCastVotes(auditInfo.castVotes, numq, numc);
                        break;
                    case 5:
                        Operations.printTrusteeList(auditInfo.trusteeList, numq, numc);
                        break;
                    case 6:
                        if(Operations.isMyVoteTallied(auditInfo.castVotes, myInfo.vote_hash))
                            System.out.println("Da, glas je uracunat.");
                        else
                            System.out.println("Ne, glas nije uracunat.");
                        break;
                    case 7:
                        if(Operations.isTheTallyCorrect(auditInfo, numq, numc))
                            System.out.println("Da, izbori su korektni.");
                        else
                            System.out.println("Ne, izbori nisu korektni.");
                        break;
                    default:
                }
                if(choose == 0)
                    break;
            }

            in.close();
            out.close();
            client.close();
        } catch (IOException | InterruptedException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyManagementException | ParseException e) {
            e.printStackTrace();
        }
    }
}
