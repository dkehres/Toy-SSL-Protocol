/*
 * This file contains the code used for ASCII conversion
 * Users will be able to input a string and obtain the 
 * the same message converted into ASCII code
 * Users will then be able to covert ASCII code back into
 * back into a string messagev<p>
 *
 * asciiConverter
 *
 * @author: Dylan Kehres
 * @date: 3/2/2018
 */
package cis435proj;

import java.math.BigInteger;

public class asciiConverter {
    private static boolean debugFlag = false;
    
    public static BigInteger strToAscii(String s){
        String inputString = s;
        char c;
        String intString = "";
        
        for (int i =0; i<inputString.length(); i++){        //loop through entire string
            c=inputString.charAt(i);        //convert single character to asii
            
            if((int)c/100==0){  //if ascii code is only 2 digits pad with zero
                intString+="0";
                intString+=(int)c;
            }
            else{
                intString+=(int)c;
            }
        }
        
        if(debugFlag == true)
            System.out.println("Integer String: "+intString);
        return new BigInteger(intString);
    }
    
    public static String asciiToString(BigInteger s){
        BigInteger zero = new BigInteger("0");
        BigInteger ten = new BigInteger("10");
        BigInteger oneThousand = new BigInteger("1000");
        BigInteger inputString = s;
        BigInteger character;
        String textString = "";
        
        if(debugFlag == true)
            System.out.println("Input String: "+inputString.toString());
        
        while(inputString.mod(ten.pow(3)).compareTo(zero)!=0){ //loop through entire BigInteger
            character = inputString.mod(ten.pow(3));        //obtain 3 digits to represent single character
            textString=(char)(character.intValue())+textString;     //convert single character
            inputString=inputString.divide(oneThousand);        //remove character from BigInteger
            
            if(debugFlag == true){
                System.out.println("Text String = "+textString);
                System.out.println("Character = "+character);
            }
        }

        return textString;
    }
    
    public static void testAsciiConverter(){
        String s = "Hello World!!!";
        BigInteger ascii = strToAscii(s);
        String outputText = asciiToString(ascii);
        
        System.out.println("\n********ASCII TO STRING TESTS********");
        System.out.println("Input String: "+s);
        System.out.println("ASCII = "+ascii);
        System.out.println("Output Text = "+outputText);
        System.out.println("********END ASCII TO STRING TESTS********\n");
    }
}
