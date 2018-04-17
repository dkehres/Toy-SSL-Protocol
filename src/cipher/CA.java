/**
*
* <p>Certificate Authority (CA) Allows user to register certificate, saves certificates,
* <p>allows user to verify certificate against public key
* 
* @author Jacob
* @date 3/1/2018
*/

package cipher;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class CA {
    
    Map<String, BigInteger> certificates;
    RSAKey publicKey;
    RSAKey privateKey;
    BigInteger hash;
    
    public CA() {
        certificates = new HashMap<>();
        // set up public private key pairs for certificate authority
        RSA rsa = new RSA();
        publicKey = rsa.getPublicKey();
        privateKey = rsa.getPrivateKey();
        hash = new BigInteger("13");
    }
    
    public Boolean registerCertificate(RSAKey keyToBeSigned, String username, String proofOfIdentity) {
        if (!isValid(username, proofOfIdentity)) {
            return false;
        }
        BigInteger message = keyToBeSigned.getExponent().add(keyToBeSigned.getN());
        // sign key
        BigInteger certificate = DigitalSignature.DigitalSignatureEncrypt(message, hash, privateKey);
        certificates.put(username, certificate);
        return true;
    }
    
    public Boolean validateKeyWithCertificate(RSAKey publicKey, BigInteger certificate) {
        BigInteger message = publicKey.getExponent().add(publicKey.getN());
        // verify digital signature of certificate to see if the key is the same
        return DigitalSignature.DigitalSignatureVerification(message, certificate, hash, this.publicKey);
    }
    
    private Boolean isValid(String username, String proofOfIdentity) {
        // for now assume everyone is who they say they are
        return !(username.equals("") || proofOfIdentity.equals(""));
    }
    
    public BigInteger getCertificate(String username) {
        return certificates.get(username);
    }
    
    public RSAKey getPublicKey() {
        return publicKey;
    }
    
    public static void testCA() {
        System.out.println("\n********CERTIFICATE AUTHORITY TESTS********");
        
        RSA rsa = new RSA();
        String name = "Bob";
        
        CA certificateAuthority = new CA();
        Boolean success = certificateAuthority.registerCertificate(rsa.getPublicKey(), name, "it's really me");
        System.out.println("should succeed");
        System.out.println("register " + (success ? "success" : "failure"));
        success = certificateAuthority.registerCertificate(rsa.getPublicKey(), "", "it's really me");
        System.out.println("should fail");
        System.out.println("register " + (success ? "success" : "failure"));
        BigInteger certificate = certificateAuthority.getCertificate(name);
        System.out.println(name + "'s certificate:\n" + certificate);
        Boolean verify = certificateAuthority.validateKeyWithCertificate(rsa.getPublicKey(), certificate);
        System.out.println("should succeed");
        System.out.println(verify ? "verified" : "not verified");
        verify = certificateAuthority.validateKeyWithCertificate(rsa.getPrivateKey(), certificate);
        System.out.println("should fail");
        System.out.println(verify ? "verified" : "not verified");
        System.out.println("********END CERTIFICATE AUTHORITY TESTS********\n");
    }
    
}
