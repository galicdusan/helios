import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.Format;
import java.util.Base64;
import java.util.Formatter;
import java.util.List;

public class Operations {

    public static boolean basicCheck(BigInteger x){
        int[] primesInt = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,
                127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,
                269,271,277,281,283,293,307,311,313,317,331,337,347,349, 353,359,367,373,379,383,389,397};

        for(int i=0; i<primesInt.length; i++){
            if (x.mod( BigInteger.valueOf( primesInt[i] ) ).equals( BigInteger.valueOf( 0 ) ) )
                return false;
        }
        return true;
    }

    public static BigInteger calculateP(){

        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(2048, random);
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

        while(basicCheck(q) == false || q.isProbablePrime(10) == false){
            p = p.nextProbablePrime();
            q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        }

        return p;
    }


    public static BigInteger preparedP(){
        return new BigInteger("22774100290761396377946474031485117061792607794922235483685908159942562892753617093964415355069955287005219097244232850449603969368465060011945083058063994672975913795064086146434782022006054592150285108506966918205975372578163186521325536516296008337932985645121713793658841166323493282343763371773789481950951030888369365841767841194773166962651181461452947132960634586202767615666079834281242819071824790796002532415601670085596974931599677368815806237857356558412438230156190731732803954383789719150241568231476269570461504449096258528486136055560315276579013333797967544285603658254961897977183575457941924198503");
    }

    public static BigInteger calculateG(BigInteger p, BigInteger q){
        SecureRandom random = new SecureRandom();
        BigInteger g = new BigInteger(p.bitLength(), random).mod(p);

        while (g.modPow(q, p).compareTo(BigInteger.ONE) != 0){
            g = g.add(BigInteger.ONE);
            if(g.compareTo(p) == 0)
                g = g.mod(p);
        }

        return g;
    }

    public static boolean isGproper(BigInteger p, BigInteger q, BigInteger g){
        SecureRandom random = new SecureRandom();
        BigInteger x = new BigInteger(q.bitLength(), random).mod(q);
        BigInteger y = g.modPow(x, p);

        if( y.modPow(q,p).compareTo(BigInteger.ONE) == 0 )
            return true;
        return false;
    }

    public static BigInteger preparedGLarge(){
        return new BigInteger("4252990971241460454543940463857829028589954392245985013917031753534260882214243286693025233630235373476780070983034348050168265162651503743844356611668450700404243436284290214383257490244924558173896640601795496380977718227307714392855615401736069591817489330792579621207131983743722622997239546274686889345839505593054298106756364659037240602973275019755026685656870281278993917616311877581024842304646478346416971482925948624458629082043698392514392258784093658985613154991191436327135125844729255027276359608066516962197528066696034664239947202237208304129065976953935274949101352043258842736192687162583264324415");
    }

    public static BigInteger preparedG2(){
        return new BigInteger("2");
    }

    public static Trustee.SecretKey createPublicKeyPair(BigInteger p, BigInteger q, BigInteger g){
        Trustee.SecretKey sk = new Trustee.SecretKey();
        sk.epk = new Server.ElgamalPublicKey();
        sk.epk.p = p;
        sk.epk.q = q;
        sk.epk.g = g;

        SecureRandom random = new SecureRandom();
        sk.secretKey = new BigInteger(q.bitLength(), random).mod(q);
        sk.epk.y = g.modPow(sk.secretKey, p);

        return sk;
    }

    public static Server.KeyProof createKeyProof(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y){
        SecureRandom random = new SecureRandom();
        BigInteger s = new BigInteger(q.bitLength(), random).mod(q);
        BigInteger a = g.modPow(s, p);

        String message = g.toString()+"+"+a.toString()+"+"+y.toString();
        String hexHash = getSHA1HexString(message);

        BigInteger e = new BigInteger(hexHash, 16).mod(q);
        BigInteger f = e.multiply(x).add(s).mod(q);

        Server.KeyProof kp = new Server.KeyProof();
        kp.commitment = a;
        kp.challenge = e;
        kp.response = f;

        return kp;
    }

    public static String getSHA1HexString(String message){
        String sha1 = "";
        try{
            MessageDigest mg = MessageDigest.getInstance("SHA-1");
            mg.reset();
            mg.update(message.getBytes("UTF-8"));
            sha1 = getHexString(mg.digest());
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return sha1;
    }

    public static String getHexString(final byte[] hash){
        Formatter formatter = new Formatter();
        for(byte b: hash)
            formatter.format("%02x", b);
        String result =formatter.toString();
        formatter.close();
        return result;
    }

    public static boolean isKeyProofValid(BigInteger a, BigInteger e, BigInteger f, BigInteger p, BigInteger q, BigInteger g, BigInteger y){
        String message = g.toString()+"+"+a.toString()+"+"+y.toString();
        String hexHash = getSHA1HexString(message);
        BigInteger test_e = new BigInteger(hexHash, 16).mod(q);
        if (test_e.compareTo(e) != 0)
            return false;
        if ( g.modPow(f, p).compareTo(  y.modPow(e, p).multiply(a).mod(p)  ) != 0 )
            return false;
        return true;
    }

    public static String getSHA1Base64String(String message){
        String sha1 = "";
        try{
            MessageDigest mg = MessageDigest.getInstance("SHA-1");
            mg.reset();
            mg.update(message.getBytes("UTF-8"));
            byte[] encodedBytes = Base64.getEncoder().encode(mg.digest());
            sha1 = new String(encodedBytes);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return sha1;
    }

    public static String getVoterHash(List<Server.Voter> voterList){
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<voterList.size(); i++){
            Server.Voter current = voterList.get(i);
            sb.append( current.voter_id+"+"+current.password+"+"+current.email+"+"+current.name+"+" );
        }
        sb.deleteCharAt( sb.length()-1 );
        return Operations.getSHA1Base64String( sb.toString() );
    }

    public static String getOneVoterHash(Server.Voter voter){
        String message = voter.voter_id+"+"+voter.password+"+"+voter.email+"+"+voter.name;
        return getSHA1Base64String( message );
    }

    public static String getElectionFingerprint(Server.Election election){
        StringBuilder sb = new StringBuilder();
        sb.append( election.name+"+"+election.voters_hash+"+"+election.pk.p+"+"+
                election.pk.q+"+"+election.pk.g+"+"+election.pk.y+"+" );
        for(int i=0; i<election.questions.size(); i++){
            Server.Question current = election.questions.get(i);
            sb.append( current.question+"+" );
            for(int j=0; j<current.answers.size(); j++){
                sb.append( current.answers.get(j)+"+" );
            }
        }
        sb.deleteCharAt( sb.length() - 1 );
        return Operations.getSHA1Base64String( sb.toString() );
    }

    public static Server.ElgamalCipherText encrypt_with_pk(Server.ElgamalPublicKey epk, BigInteger m, BigInteger r){
        Server.ElgamalCipherText result = new Server.ElgamalCipherText();
        result.c1 = epk.g.modPow(r, epk.p);
        result.c2 = epk.y.modPow(r, epk.p).multiply(m).mod(epk.p);
        return result;
    }

    public static void prepareProofs(List<Server.VoteProof> proofs, Server.ElgamalPublicKey epk, Server.ElgamalCipherText ect, BigInteger m, BigInteger r){
        BigInteger m1, m2;
        m1 = epk.g.pow( 1 );
        m2 = epk.g.pow( 0 );
        if( m.compareTo( epk.g.pow( 1 ) ) == 0 )
        {
            m1 = epk.g.pow( 0 );
            m2 = m;
        }

        SecureRandom random = new SecureRandom();
        BigInteger e = new BigInteger(epk.q.bitLength(), random).mod(epk.q);
        BigInteger f = new BigInteger(epk.q.bitLength(), random).mod(epk.q);

        BigInteger c2_over_m1 = m1.modInverse(epk.p).multiply(ect.c2).mod(epk.p);
        Server.VoteProof fakeProof = new Server.VoteProof();
        fakeProof.challenge = e;
        fakeProof.response = f;
        BigInteger temp1 = ect.c1.modPow(e, epk.p).modInverse(epk.p);
        BigInteger temp2 = epk.g.modPow(f, epk.p);
        fakeProof.commitA = temp1.multiply( temp2 ).mod(epk.p);
        temp1 = c2_over_m1.modPow(e, epk.p).modInverse(epk.p);
        temp2 = epk.y.modPow(f, epk.p);
        fakeProof.commitB = temp1.multiply( temp2 ).mod(epk.p);


        BigInteger s = new BigInteger(epk.q.bitLength(), random).mod(epk.q);
        Server.VoteProof realProof = new Server.VoteProof();
        realProof.commitA = epk.g.modPow(s, epk.p);
        realProof.commitB = epk.y.modPow(s, epk.p);

        String message = null;
        if( m.compareTo( epk.g.pow( 1 ) ) == 0 )
            message = epk.g.toString()+"+"+
                fakeProof.commitA.toString()+"+"+fakeProof.commitB.toString()+"+"+
                realProof.commitA.toString()+"+"+realProof.commitB.toString()+"+"+
                epk.y.toString();
        else
            message = epk.g.toString()+"+"+
                realProof.commitA.toString()+"+"+realProof.commitB.toString()+"+"+
                fakeProof.commitA.toString()+"+"+fakeProof.commitB.toString()+"+"+
                epk.y.toString();

        String hexHash = getSHA1HexString(message);
        BigInteger global_e = new BigInteger(hexHash, 16).mod(epk.q);
        realProof.challenge = global_e.subtract(e).mod(epk.q);
        realProof.response = realProof.challenge.multiply(r).add(s).mod(epk.q);

        if( m.compareTo( epk.g.pow( 1 ) ) == 0 ){
            proofs.add(fakeProof);
            proofs.add(realProof);
        } else {
            proofs.add(realProof);
            proofs.add(fakeProof);
        }

    }

    public static Server.ElgamalCipherText homomorphic_add(Server.ElgamalCipherText a, Server.ElgamalCipherText b, Server.ElgamalPublicKey epk){
        Server.ElgamalCipherText sum = new Server.ElgamalCipherText();
        sum.c1 = a.c1.multiply(b.c1).mod(epk.p);
        sum.c2 = a.c2.multiply(b.c2).mod(epk.p);
        return sum;
    }

    public static boolean verifySingleProof(Server.ElgamalPublicKey epk, Server.ElgamalCipherText ect, BigInteger m, Server.VoteProof proof){
        BigInteger temp1 = epk.g.modPow(proof.response, epk.p);
        BigInteger temp2 = ect.c1.modPow(proof.challenge, epk.p).multiply(proof.commitA).mod(epk.p);
        if (temp1.compareTo(temp2) != 0)
            return false;

        BigInteger temp3 = m.modInverse(epk.p).multiply(ect.c2).mod(epk.p);
        temp1 = epk.y.modPow(proof.response, epk.p);
        temp2 = temp3.modPow(proof.challenge, epk.p).multiply(proof.commitB).mod(epk.p);
        if (temp1.compareTo(temp2) != 0)
            return false;

        return true;
    }

    public static boolean verifyBothProofs(int index, List<Server.VoteProof> proofs, Server.ElgamalPublicKey epk, Server.ElgamalCipherText ect){
        BigInteger one = epk.g.pow( 1 );
        BigInteger zero = epk.g.pow( 0 );
        if( !verifySingleProof(epk, ect, zero, proofs.get(index) ) )
            return false;
        if( !verifySingleProof(epk, ect, one, proofs.get(index+1) ) )
            return false;

        BigInteger computed_e = proofs.get(index).challenge.add( proofs.get(index+1).challenge ).mod(epk.q);
        String message = epk.g.toString()+"+"+
                proofs.get(index).commitA.toString()+"+"+proofs.get(index).commitB.toString()+"+"+
                proofs.get(index+1).commitA.toString()+"+"+proofs.get(index+1).commitB.toString()+"+"+
                epk.y.toString();
        BigInteger expected_e = new BigInteger( getSHA1HexString(message), 16 ).mod(epk.q);
        if (computed_e.compareTo( expected_e ) == 0)
            return true;
        return false;
    }

    public static boolean verifyVote(String fingerprint, Server.Vote vote, Server.ElgamalPublicKey epk){
        if (!vote.election_fingerprint.equals(fingerprint))
            return false;

        for (Server.EncryptedAnswer answer : vote.answers){
            Server.ElgamalCipherText sum = new Server.ElgamalCipherText();
            sum.c1 = BigInteger.ONE;
            sum.c2 = BigInteger.ONE;

            for (int i=0; i<answer.choices.size(); i++){
                Server.ElgamalCipherText ect = answer.choices.get(i);
                if (!verifyBothProofs( i*2, answer.proofs, epk, ect ))
                    return false;
                sum = homomorphic_add(sum, ect, epk);
            }

            if(!verifyBothProofs( 0, answer.overallProof, epk, sum ))
                return false;
        }
        return true;
    }

    public static String getVoteHash(Server.Vote vote){
        StringBuilder sb = new StringBuilder();
        sb.append( vote.election_fingerprint+"+" );
        for(Server.EncryptedAnswer answer: vote.answers){
            for(Server.ElgamalCipherText ect: answer.choices)
                sb.append(ect.c1.toString()+"+"+ect.c2.toString()+"+");
            for(Server.VoteProof proof: answer.overallProof)
                sb.append(proof.challenge.toString()+"+"+proof.commitA+"+"+proof.commitB+"+"+proof.response.toString()+"+");
            for(Server.VoteProof proof: answer.proofs)
                sb.append(proof.challenge.toString()+"+"+proof.commitA+"+"+proof.commitB+"+"+proof.response.toString()+"+");
        }
        sb.deleteCharAt( sb.length() - 1 );
        return getSHA1Base64String( sb.toString() );
    }

    public static String getAuditVoteHash(Server.AuditVote vote){
        StringBuilder sb = new StringBuilder();
        sb.append( vote.election_fingerprint+"+" );
        for(Server.AuditEncryptedAnswer answer: vote.answers){
            for(Server.ElgamalCipherText ect: answer.choices)
                sb.append(ect.c1.toString()+"+"+ect.c2.toString()+"+");
            for(Server.VoteProof proof: answer.overallProof)
                sb.append(proof.challenge.toString()+"+"+proof.commitA+"+"+proof.commitB+"+"+proof.response.toString()+"+");
            for(Server.VoteProof proof: answer.proofs)
                sb.append(proof.challenge.toString()+"+"+proof.commitA+"+"+proof.commitB+"+"+proof.response.toString()+"+");
        }
        sb.deleteCharAt( sb.length() - 1 );
        return getSHA1Base64String( sb.toString() );
    }

    public static boolean auditBallot(String fingerprint, String vote_hash, Server.AuditVote auditVote, Server.Vote vote, Server.ElgamalPublicKey epk){
        String vote_hash2 = getVoteHash(vote);
        String audit_vote_hash = getAuditVoteHash(auditVote);
        if( !(vote_hash.equals(vote_hash2) && vote_hash2.equals(audit_vote_hash)) )
            return false;

        if( !verifyVote(fingerprint, vote, epk) )
            return false;

        for(Server.AuditEncryptedAnswer answer: auditVote.answers){
            for(int i=0; i<answer.choices.size(); i++){
                Server.ElgamalCipherText ect = answer.choices.get(i);
                BigInteger r = answer.randomness.get(i);
                BigInteger m = null;
                if(answer.answer == i+1)
                    m = epk.g.pow( 1 );
                else
                    m = epk.g.pow( 0 );

                if( epk.g.modPow(r, epk.p).compareTo( ect.c1 ) != 0 )
                    return false;
                BigInteger c2 = epk.y.modPow(r, epk.p).multiply(m).mod(epk.p);
                if( c2.compareTo(ect.c2) != 0 )
                    return false;
            }
        }
///////////////////////////////////////
        System.out.println("Izgled auditable glasa: ");
        System.out.println("Election fingerprint: "+ auditVote.election_fingerprint);
        for(int i=0; i<auditVote.answers.size(); i++){
            Server.AuditEncryptedAnswer answer = auditVote.answers.get(i);
            System.out.println("Neenkriptovan odgovor na pitanje "+(i+1)+": "+answer.answer);
            System.out.println("Enkriptovani odgovori za pitanje "+(i+1)+": ");
            for(int j=0; j<answer.choices.size(); j++){
                System.out.print( answer.choices.get(j).c1+", "+answer.choices.get(j).c2+", ");
            }
            System.out.println();

            System.out.println("Nasumicne vrednosti(randomness) koriscene za enkripicju odgovora: ");
            for(int j=0; j<answer.choices.size(); j++){
                System.out.print( answer.randomness.get(j)+", " );
            }
            System.out.println();

            System.out.println("Dokazi za odgovore: ");
            for(int j=0; j<answer.proofs.size(); j++){
                System.out.print( answer.proofs.get(j).challenge+","
                        +answer.proofs.get(j).commitA+","+
                        answer.proofs.get(j).commitB+","+answer.proofs.get(j).response+",");
            }
            System.out.println();

            System.out.println("Dokazi za zbir odgovora: ");
            for(int j=0; j<2; j++){
                System.out.print( answer.overallProof.get(j).challenge+", "+
                        answer.overallProof.get(j).commitA+", "+
                        answer.overallProof.get(j).commitB+", "+
                        answer.overallProof.get(j).response+", ");
            }
            System.out.println();

        }
///////////////////////////
        return true;
    }

    public static Server.VoteProof getDecryptionProof(Server.ElgamalPublicKey epk, Server.ElgamalCipherText ect, Trustee.SecretKey secretKey){
        Server.VoteProof proof = new Server.VoteProof();

        SecureRandom random = new SecureRandom();
        BigInteger s = new BigInteger(epk.q.bitLength(), random).mod(epk.q);

        proof.commitA = epk.g.modPow( s, epk.p );
        proof.commitB = ect.c1.modPow( s, epk.p );

        String message = epk.g.toString()+"+"+proof.commitA.toString()+"+"+proof.commitB.toString()+"+"+epk.y.toString();
        String hexHash = getSHA1HexString(message);
        BigInteger e = new BigInteger(hexHash, 16).mod(epk.q);

        proof.challenge = e;
        proof.response = secretKey.secretKey.multiply(e).add(s).mod(epk.q);

        return proof;
    }

    public static boolean isDecryptionProofValid(Server.VoteProof proof, Server.ElgamalPublicKey epk, Server.ElgamalCipherText ect, BigInteger di){
        String message = epk.g.toString()+"+"+proof.commitA.toString()+"+"+proof.commitB.toString()+"+"+epk.y.toString();
        BigInteger e = new BigInteger( getSHA1HexString(message), 16).mod(epk.q);
        if( e.compareTo(proof.challenge) != 0 )
            return false;

        BigInteger temp1 = epk.g.modPow(proof.response, epk.p);
        BigInteger temp2 = epk.y.modPow(proof.challenge, epk.p).multiply(proof.commitA).mod(epk.p);
        if( temp1.compareTo( temp2 ) != 0 )
            return false;

        temp1 = ect.c1.modPow(proof.response, epk.p);
        temp2 = di.modPow(proof.challenge, epk.p).multiply(proof.commitB).mod(epk.p);
        if( temp1.compareTo( temp2 ) != 0 )
            return false;

        return true;
    }

    public static void printElection(Server.Election election, int numq, int[] numc){
        System.out.println("Enkriptovani rezultat glasanja:");
        for(int i=0; i<numq; i++) {
            System.out.println("Pitanje: "+(i+1));
            for (int j = 0; j < numc[i]; j++) {
                System.out.print(election.tally[i][j].c1 + "  " + election.tally[i][j].c2 + "  ,");
            }
            System.out.println();
        }

        System.out.println("Election P, Q, G, Y");
        System.out.println(election.pk.p);
        System.out.println(election.pk.q);
        System.out.println(election.pk.g);
        System.out.println(election.pk.y);
        System.out.println("Election fingerprint i voters hash");
        System.out.println(election.fingerprint+", "+election.voters_hash);
        System.out.println();
        System.out.println();
    }

    public static void printVoterList(List<Server.Voter> voterList, int numq, int[] numc){
        System.out.println("Lista glasaca: ");
        for(int i=0; i<voterList.size(); i++){
            Server.Voter current = voterList.get(i);
            System.out.println("Glasac: id, email, ime");
            System.out.println( current.voter_id+", "+current.email+", "+current.name);

        }

        System.out.println();
        System.out.println();
    }

    public static void printResult(Server.Result result, int numq, int[] numc){
        System.out.println("Konacni rezultat glasanja: ");
        for(int i=0; i<numq; i++) {
            System.out.println("Pitanje: " + (i + 1));
            for (int j = 0; j < numc[i]; j++) {
                System.out.print("Izbor "+(j+1)+": "+result.count[i][j] +" ");
            }
            System.out.println();
        }
        System.out.println();
        System.out.println();
    }

    public static void printCastVotes(List<Server.CastVote> castVotes, int numq, int[] numc){
        System.out.println("Lista ubacenih glasova: ");
        for(int k=0; k<castVotes.size(); k++){
            Server.CastVote cv = castVotes.get(k);
            System.out.println("Glas: vreme, hes glasa, hes glasaca, id glasaca, fingerprint izbora");
            System.out.println( cv.castTime.toString()+", "+cv.vote_hash+", "+cv.voter_hash+", "+cv.voter_id+", "+cv.vote.election_fingerprint);

            for(int i=0; i<numq; i++){
                Server.EncryptedAnswer answer = cv.vote.answers.get(i);
                System.out.println("Enkriptovani odgovori za pitanje "+(i+1)+": ");
                for(int j=0; j<numc[i]; j++){
                    System.out.print( answer.choices.get(j).c1+", "+answer.choices.get(j).c2+", ");
                }
                System.out.println();

                System.out.println("Dokazi za odgovore: ");
                for(int j=0; j<numc[i]*2; j++){
                    System.out.print( answer.proofs.get(j).challenge+","
                            +answer.proofs.get(j).commitA+","+
                            answer.proofs.get(j).commitB+","+answer.proofs.get(j).response+",");
                }
                System.out.println();

                System.out.println("Dokazi za zbir odgovora: ");
                for(int j=0; j<2; j++){
                    System.out.print( answer.overallProof.get(j).challenge+", "+
                            answer.overallProof.get(j).commitA+", "+
                            answer.overallProof.get(j).commitB+", "+
                            answer.overallProof.get(j).response+", ");
                }
                System.out.println();

            }

        }
        System.out.println();
        System.out.println();
    }

    public static void printTrusteeList(List<Server.Trustee> trusteeList, int numq, int[] numc){
        System.out.println("Lista svih poverenika: ");
        for(int k=0; k<trusteeList.size(); k++){
            Server.Trustee trustee = trusteeList.get(k);
            System.out.println("Poverenik: id");
            System.out.println( trustee.id);
            System.out.println("Javni kljuc poverenika: p, q, g ,y");
            System.out.println( trustee.epk.p);
            System.out.println( trustee.epk.q);
            System.out.println( trustee.epk.g);
            System.out.println( trustee.epk.y);
            System.out.println("Dokaz ispravnosti kljuca:");
            System.out.println(trustee.kp.challenge+", "+trustee.kp.commitment+", "+trustee.kp.response);

            System.out.println("Dekripcije: ");
            for(int i=0; i<numq; i++)
                for(int j=0; j<numc[i]; j++){
                   System.out.println( trustee.partialDecrypt[i][j]);
                }

            System.out.println("Dokazi ispravnosti dekripcija: ");
            for(int i=0; i<numq; i++)
                for(int j=0; j<numc[i]; j++){
                    System.out.println( trustee.proofs[i][j].challenge+", "+trustee.proofs[i][j].commitA+", "+
                            trustee.proofs[i][j].commitB+", "+trustee.proofs[i][j].response+", ");
                }
        }
        System.out.println();
        System.out.println();
    }

    public static boolean isMyVoteTallied(List<Server.CastVote> castVotes, String vote_hash){
        for(Server.CastVote castVote: castVotes){
            if(castVote.vote_hash.equals( vote_hash ))
                return true;
        }
        return false;
    }

    public static boolean isTheTallyCorrect(Voter.AuditInfo auditInfo, int numq, int[] numc){
        String computed_fingerprint = getElectionFingerprint(auditInfo.election);
        if(!computed_fingerprint.equals( auditInfo.election.fingerprint ))
            return false;

        System.out.println("Sracunat fingerprint izbora: ");
        System.out.println(computed_fingerprint);

        String computed_voterHash = getVoterHash(auditInfo.voterList);
        if(!computed_voterHash.equals( auditInfo.election.voters_hash ))
            return false;

        for(Server.CastVote castVote: auditInfo.castVotes){
            if(!Operations.verifyVote(auditInfo.election.fingerprint, castVote.vote, auditInfo.election.pk))
                return false;
        }

        System.out.println("Lista ballot tracker-a ubacenih glasova: ");
        for(Server.CastVote castVote: auditInfo.castVotes){
            System.out.println(castVote.vote_hash);
        }

        Server.ElgamalCipherText[][] tally = new Server.ElgamalCipherText[numq][30];
        for(int i=0; i<numq; i++){
            Server.Question currq = auditInfo.election.questions.get(i);

            for(int j=0; j<currq.answers.size(); j++){
                Server.ElgamalCipherText sum = new Server.ElgamalCipherText();
                sum.c1 = BigInteger.ONE;
                sum.c2 = BigInteger.ONE;

                for(Server.CastVote cv: auditInfo.castVotes){
                    Server.ElgamalCipherText ect = cv.vote.answers.get(i).choices.get(j);
                    sum = Operations.homomorphic_add(sum, ect, auditInfo.election.pk);
                }
                tally[i][j] = sum;
                if(tally[i][j].c1.compareTo( auditInfo.election.tally[i][j].c1 ) != 0)
                    return false;
                if(tally[i][j].c2.compareTo( auditInfo.election.tally[i][j].c2 ) != 0)
                    return false;
            }
        }

        Server.Result result = new Server.Result();
        result.count = new int [numq][30];
        for(int i=0; i<numq; i++) {

            for (int j = 0; j < auditInfo.election.questions.get(i).answers.size(); j++) {
                BigInteger product = BigInteger.ONE;
                for (Server.Trustee trustee : auditInfo.trusteeList) {
                    product = product.multiply(trustee.partialDecrypt[i][j]).mod(auditInfo.election.pk.p);
                    if (!Operations.isDecryptionProofValid(trustee.proofs[i][j], trustee.epk, auditInfo.election.tally[i][j], trustee.partialDecrypt[i][j]))
                        return false;
                }
                BigInteger temp = product.modInverse(auditInfo.election.pk.p).multiply(auditInfo.election.tally[i][j].c2).mod(auditInfo.election.pk.p);
                result.count[i][j] = (temp.bitLength() -1) / (auditInfo.election.pk.g.bitLength() - 1 );
                if(result.count[i][j] != auditInfo.result.count[i][j])
                    return false;
            }

        }
        return true;
    }

/*    public static void main(String[] args) {
        BigInteger p = calculateP();
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        System.out.println( p);
        System.out.println( q);
        BigInteger p = new BigInteger("22774100290761396377946474031485117061792607794922235483685908159942562892753617093964415355069955287005219097244232850449603969368465060011945083058063994672975913795064086146434782022006054592150285108506966918205975372578163186521325536516296008337932985645121713793658841166323493282343763371773789481950951030888369365841767841194773166962651181461452947132960634586202767615666079834281242819071824790796002532415601670085596974931599677368815806237857356558412438230156190731732803954383789719150241568231476269570461504449096258528486136055560315276579013333797967544285603658254961897977183575457941924198503");
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        System.out.println( p.isProbablePrime(10) );
        System.out.println( q.isProbablePrime(10) );
    } */

/*    public static void main(String[] args) {
        BigInteger p = preparedP();
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        System.out.println( calculateG(p,q) );
        System.out.println( BigInteger.valueOf(2).modPow(q,p));
    }
*/
/*    public static void main(String[] args) {
        BigInteger p = preparedP();
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        BigInteger g = preparedG2();
//        BigInteger g = preparedGLarge();
        Trustee.SecretKey sk = createPublicKeyPair(p,q,g);
        System.out.println( isGproper(p,q,g) );
    }

 */

}
