# Franklin-Reiter attack against RSA.
# If two messages differ only by a known fixed difference between the two messages
# and are RSA encrypted under the same RSA modulus N
# then it is possible to recover both of them.

# Inputs are modulus, known difference, ciphertext 1, ciphertext2.
# Ciphertext 1 corresponds to smaller of the two plaintexts. (The one without the fixed difference added to it)
def franklinReiter(n,e,r,c1,c2):
    R.<X> = Zmod(n)[]
    f1 = X^e - c1
    f2 = (X + r)^e - c2
    # coefficient 0 = -m, which is what we wanted!
    return Integer(n-(compositeModulusGCD(f1,f2)).coefficients()[0])

  # GCD is not implemented for rings over composite modulus in Sage
  # so we do our own implementation. Its the exact same as standard GCD, but with
  # the polynomials monic representation
def compositeModulusGCD(a, b):
    if(b == 0):
        return a.monic()
    else:
        return compositeModulusGCD(b, a % b)

def CoppersmithShortPadAttack(e,n,C1,C2,eps=1/30):
    """
    Coppersmith's Shortpad attack!
    Figured out from: https://en.wikipedia.org/wiki/Coppersmith's_attack#Coppersmith.E2.80.99s_short-pad_attack
    """
    import binascii
    P.<x,y> = PolynomialRing(ZZ)
    ZmodN = Zmod(n)
    g1 = x^e - C1
    g2 = (x+y)^e - C2
    res = g1.resultant(g2)
    P.<y> = PolynomialRing(ZmodN)
    # Convert Multivariate Polynomial Ring to Univariate Polynomial Ring
    rres = 0
    for i in range(len(res.coefficients())):
        rres += res.coefficients()[i]*(y^(res.exponents()[i][1]))

    diff = rres.small_roots(epsilon=eps)
    recoveredM1 = franklinReiter(n,e,diff[0],C1,C2)
    recoveredM2 = recoveredM1 + diff[0]
    print(recoveredM1)
    print(recoveredM2)



def testCoppersmithShortPadAttack(eps=1/25):
    from Crypto.PublicKey import RSA
    import random
    import math
    import binascii
    M = "flag{This_Msg_Is_2_1337}"
    M = int(binascii.hexlify(M),16)
    e = 3
    nBitSize =  8192
    key = RSA.generate(nBitSize)
    #Give a bit of room, otherwhise the epsilon has to be tiny, and small roots will take forever
    m = int(math.floor(nBitSize/(e*e))) - 400
    assert (m < nBitSize - len(bin(M)[2:]))
    r1 = random.randint(1,pow(2,m))
    r2 = random.randint(r1,pow(2,m))
    M1 = pow(2,m)*M + r1
    M2 = pow(2,m)*M + r2
    C1 = Integer(pow(M1,e,key.n))
    C2 = Integer(pow(M2,e,key.n))
    CoppersmithShortPadAttack(e,key.n,C1,C2,eps)

def testFranklinReiter():
    p = random_prime(2^512)
    q = random_prime(2^512)
    n = p * q # 1024-bit modulus
    e = 11

    m = randint(0, n) # some message we want to recover
    r = randint(0, n) # random padding

    c1 = pow(m + 0, e, n)
    c2 = pow(m + r, e, n)
    print(m)
    recoveredM = franklinReiter(n,e,r,c1,c2)
    print(recoveredM)
    assert recoveredM==m
    print("They are equal!")
    return True

n = 18430448295927913206646907226076164929458329526077999995222414616052836515898301137278993025432210434790210393836134858118110344752402822082427959416410880280597129375841938702629336045578608257825966418557238363670808557331434560599035356019407459218275025526772209640862607640710723006743507632077516654627998795539260878973583152797208023671860440020523036945169054170666558650199369709846010016621221635402263842258311469371070558175226354591843258350008576808520704946820474098578076398393262338839376444109504785722024570456077852127568061056091020176362292604289875749551748600904432044806119959149087228579409
e = 5
C1 = 5168842558581559358010711589702806678101223808847307664257735927619675199771789591306984392223284584584338085540743443304868756823519082777743365047194791184703261384690797324615445107438378431972330914541747232702374137131509063440808643569731898753676733567429631978126115617494572685297543758386894176034531297633511003026823334190221344851997193291005414155191907886757217847421069473031044782826501232945312491860947306491883797749246714415487397263022230105495836954753843486855489530586161443813894342563207332211824483016017881537963673657132741908293421722794040456346891742156466045952556815080993011917212
C2 = 18260780475559786483357755376934470327557519424777192089161460586217552390905089353939018022487454343578632606490680281497994757763709306235061679080528636531817999851181931029790748781005626663771386993530587856358124674282220150141613915357185759011115325901224886228264632015243751965776750653896405282709168747937288206208309717715634000736872672004346231874583755377864399780683167596638147572495033547022962097741688736784200068574300598626567962778723027448650135157060951500291345227580162668560873677662514056195422282944690971704126234056420197918938850746035646344512188008880403913109057173333076190133328

CoppersmithShortPadAttack(e,n,C1,C2,eps=1/100)