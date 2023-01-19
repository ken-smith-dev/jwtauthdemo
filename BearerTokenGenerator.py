import sys
import requests
import jwt
import time

ClientID = "CLIENTID" # The clientID registered with the OAuth server
TokenEndpoint = "https://some-oauth-server.com/oauth2/token" # Where to request the token
TargetFHIREndpoint = "https://some-fhir-server.com/fhir/r4" # Where you are trying to access
privateKey = open('some-privatekey.pem', 'r').read() # The private key in pem format.  The public key needs to be loaded on the OAuth2 server

def main():
    jwtEncoded = generateEncodedJWT()
    bearerToken = getBearerToken(jwtEncoded)
    print(bearerToken)

def generateEncodedJWT():
    """Generates a JWT and encodes it using a private key and a specified
    algorithm.  The OAuth server also needs to know which algorithm to use"""
    
    currentEpochTime = int(time.time()) # EpochTime is used to calculate token expiry
    jwtArray = {}

    jwtArray.update({"iss": ClientID})
    jwtArray.update({"sub": ClientID})
    jwtArray.update({"aud": TargetFHIREndpoint}) # note: Multiple aud parameters can be specified in an array
    jwtArray.update({"exp": currentEpochTime + 300}) # Token expiry - I set it to 5 mins (300sec)
    jwtArray.update({"jti": currentEpochTime + 300}) # JTI usually just needs to be a unique number.  I just use the same value as the expiry

    jwtEncoded = jwt.encode(jwtArray,privateKey,algorithm="RS384") # May need to change the algorithm to match the server settings/key parameters

    return jwtEncoded

def getBearerToken(encodedJWT):
    """Takes an encodedJWT, submits a REST request to the token endpoint, and 
    returns the access token from the response"""
    requestBody = {} # Create the body of the request
    requestBody.update({"grant_type": "client_credentials"})
    requestBody.update({"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"})
    requestBody.update({"client_assertion": encodedJWT})

    response = requests.post(TokenEndpoint, data=requestBody) # Submits request

    responseObject = response.json() # Response should include the access_token if it was successful
    # print(responseObject) # Uncomment this for debugging

    return responseObject.get("access_token")

if __name__ == '__main__':
    sys.exit(main())