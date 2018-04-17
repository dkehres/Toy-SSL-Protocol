/**
*
* <p>RSA Key (RSAKey) Represents a public or private RSA key, stores exponent and n
* 
* 
* @author Jacob
* @date 3/1/2018
*/

package cipher;

import java.math.BigInteger;

public class RSAKey {
    private final BigInteger exponent;
    private final BigInteger n;
    
    public RSAKey(BigInteger n, BigInteger exponent) {
        this.exponent = exponent;
        this.n = n;
    }
    
    public BigInteger getExponent() {
        return exponent;
    }
    
    public BigInteger getN() {
        return n;
    }
}
