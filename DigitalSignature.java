import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class DigitalSignature {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
        try{
            SignerUser  signer = new SignerUser ();
            String message = "This is the first message";
                             
            byte[] sign = signMessage(message.getBytes(), signer.getPrivateKey());
            PublicKey pubKey = signer.getPubKey();
            validateMessageSignature(pubKey, message.getBytes(), sign);
            
            
            String message2 = "This is the second message";
            byte[] sign2 = signMessage(message2.getBytes(), signer.getPrivateKey());
            validateMessageSignature(pubKey, message2.getBytes(), sign2);

    }catch(Exception e){
        e.printStackTrace();
    }
		
	}
	
	

    public static void validateMessageSignature(PublicKey publicKey, byte[] message, byte[] signature) throws
    NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature clientSig = Signature.getInstance("DSA");
    clientSig.initVerify(publicKey);
    clientSig.update(message);
    if (clientSig.verify(signature)) {
       System.out.println("The message is properly signed.");
    } else {
       System.err.println("It is not possible to validate the signature.");
    }
}
	
	public static byte[] signMessage(byte[] message,PrivateKey privateKey) throws NoSuchAlgorithmException,
    InvalidKeyException, SignatureException {
          Signature sig = Signature.getInstance("DSA");
          sig.initSign(privateKey);
          sig.update(message);
          byte[] sign= sig.sign();
          return sign;
    }
	
	
	
    public static class SignerUser {
        private PublicKey publicKey;
        private PrivateKey privateKey;
        public PublicKey getPubKey() {
              return publicKey;
        }
        
        public SignerUser() throws NoSuchAlgorithmException{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            SecureRandom secRan = new SecureRandom();
            kpg.initialize(512, secRan);
            KeyPair keyP = kpg.generateKeyPair();
            this.publicKey= keyP.getPublic();
            this.privateKey = keyP.getPrivate();
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }
        
        


    }
}
