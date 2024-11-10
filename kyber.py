from typing import List, Tuple
import hashlib
import os
from functools import reduce


class ShakeStream:
    def __init__(self, fonction_digest) -> None:
        # fonction_digest est une fonction qu'on peut appeler plusieurs fois avec différentes tailles
        self.digest = fonction_digest
        self.tampon = self.digest(32)  # longueur initiale arbitraire
        self.decalage = 0
    
    def lire(self, n: int) -> bytes:
        # Doubler la taille du tampon jusqu'à avoir suffisamment de données
        while self.decalage + n > len(self.tampon):
            self.tampon = self.digest(len(self.tampon) * 2)
        resultat = self.tampon[self.decalage:self.decalage + n]
        self.decalage += n
        return resultat


# Paramètres ML-KEM-768 :
N = 256
Q = 3329
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

def inversion_bits7(n: int) -> int:
    """
    Inverse les bits d'un entier sur 7 bits.

    Paramètres :
    n : int : Un entier dont les 7 bits doivent être inversés.

    Retourne :
    int : L'entier résultant après inversion des bits.
    """
    return int(f"{n:07b}"[::-1], 2)

# 17 est une racine primitive 256ème de l'unité modulo Q
ZETA = [pow(17, inversion_bits7(k), Q) for k in range(128)]  # Utilisé dans ntt et ntt_inv
GAMMA = [pow(17, 2 * inversion_bits7(k) + 1, Q) for k in range(128)]  # Utilisé dans ntt_mul


# Peut être réutilisé pour les représentants NTT
def poly256_add(a: List[int], b: List[int]) -> List[int]:
    """Addition de deux polynômes modulo Q, coefficient par coefficient."""
    return [(x + y) % Q for x, y in zip(a, b)]

def poly256_sub(a: List[int], b: List[int]) -> List[int]:
    """Soustraction de deux polynômes modulo Q, coefficient par coefficient."""
    return [(x - y) % Q for x, y in zip(a, b)]


# Effectue la Transformée Numérique Théorique (NTT)
def ntt(f_entree: List[int]) -> List[int]:
    """Effectue la Transformée Numérique Théorique (NTT) d'un polynôme donné."""
    f_sortie = f_entree.copy()  
    indice_racine = 1  
    for log2longueur in range(7, 0, -1):  
        longueur_bloc = 2**log2longueur  
        for debut in range(0, 256, 2 * longueur_bloc):  
            racine_unite = ZETA[indice_racine] 
            indice_racine += 1  
            for j in range(debut, debut + longueur_bloc):  
                temp = (racine_unite * f_sortie[j + longueur_bloc]) % Q  
                f_sortie[j + longueur_bloc] = (f_sortie[j] - temp) % Q  
                f_sortie[j] = (f_sortie[j] + temp) % Q  
    return f_sortie  


# Fonction inverse de la NTT (Transformée Numérique Théorique Inverse)
def ntt_inv(f_entree: List[int]) -> List[int]:
    """Effectue la Transformée Numérique Théorique Inverse (NTT inverse) d'un polynôme donné."""
    f_sortie = f_entree.copy()  
    indice_racine = 127  
    for log2longueur in range(1, 8):  
        longueur_bloc = 2**log2longueur  
        for debut in range(0, 256, 2 * longueur_bloc):  
            racine_unite = ZETA[indice_racine]  
            indice_racine -= 1  
            for j in range(debut, debut + longueur_bloc):  
                t = f_sortie[j]  
                f_sortie[j] = (t + f_sortie[j + longueur_bloc]) % Q  
                f_sortie[j + longueur_bloc] = (racine_unite * (f_sortie[j + longueur_bloc] - t)) % Q  

    for i in range(256):
        f_sortie[i] = (f_sortie[i] * 3303) % Q  # Normalisation avec l'inverse de 128 modulo Q

    return f_sortie  


ntt_add = poly256_add  # C'est simplement une addition élément par élément

# Et ceci est juste O(n)
def ntt_mul(a: List[int], b: List[int]) -> List[int]:
    c = []
    for i in range(128):
        a0, a1 = a[2 * i: 2 * i + 2]
        b0, b1 = b[2 * i: 2 * i + 2]
        c.append((a0 * b0 + a1 * b1 * GAMMA[i]) % Q)
        c.append((a0 * b1 + a1 * b0) % Q)
    return c


# Fonctions cryptographiques

def mlkem_prf(eta: int, data: bytes, b: int) -> bytes:
    """Fonction PRF utilisée dans ML-KEM pour générer des clés ou des valeurs."""
    return hashlib.shake_256(data + bytes([b])).digest(64 * eta)

def mlkem_xof(data: bytes, i: int, j: int) -> ShakeStream:
    """Fonction pour générer un flux de données XOF (Extendable Output Function)."""
    return ShakeStream(hashlib.shake_128(data + bytes([i, j])).digest)

def mlkem_hash_H(data: bytes) -> bytes:
    """Fonction de hachage H utilisée dans ML-KEM."""
    return hashlib.sha3_256(data).digest()

def mlkem_hash_J(data: bytes) -> bytes:
    """Fonction de hachage J utilisée dans ML-KEM."""
    return hashlib.shake_256(data).digest(32)

def mlkem_hash_G(data: bytes) -> bytes:
    """Fonction de hachage G utilisée dans ML-KEM."""
    return hashlib.sha3_512(data).digest()


# Logique d'encodage/décodage

def bits_to_bytes(bits: List[int]) -> bytes:
    """Convertit une liste de bits en bytes."""
    assert(len(bits) % 8 == 0)
    return bytes(
        sum(bits[i + j] << j for j in range(8))
        for i in range(0, len(bits), 8)
    )

def bytes_to_bits(data: bytes) -> List[int]:
    """Convertit des bytes en une liste de bits."""
    bits = []
    for word in data:
        for i in range(8):
            bits.append((word >> i) & 1)
    return bits

def byte_encode(d: int, f: List[int]) -> bytes:
    """Encode les valeurs d'un polynôme en bytes."""
    assert(len(f) == 256)
    bits = []
    for a in f:
        for i in range(d):
            bits.append((a >> i) & 1)
    return bits_to_bytes(bits)

def byte_decode(d: int, data: bytes) -> List[int]:
    """Décode des bytes en une liste d'entiers."""
    bits = bytes_to_bits(data)
    return [sum(bits[i * d + j] << j for j in range(d)) for i in range(256)]

def compress(d: int, x: List[int]) -> List[int]:
    """Compresse une liste d'entiers en utilisant le paramètre d."""
    return [(((n * 2**d) + Q // 2 ) // Q) % (2**d) for n in x]

def decompress(d: int, x: List[int]) -> List[int]:
    """Décompresse une liste d'entiers."""
    return [(((n * Q) + 2**(d-1) ) // 2**d) % Q for n in x]


# Échantillonnage

def sample_ntt(xof: ShakeStream):
    """Échantillonne des coefficients pour un polynôme dans le domaine NTT."""
    res = []
    while len(res) < 256:
        a, b, c = xof.lire(3)
        d1 = ((b & 0xf) << 8) | a
        d2 = c << 4 | b >> 4
        if d1 < Q:
            res.append(d1)
        if d2 < Q and len(res) < 256:
            res.append(d2)
    return res


def sample_poly_cbd(eta: int, data: bytes) -> List[int]:
    """Échantillonne un polynôme en utilisant une méthode CBD."""
    assert(len(data) == 64 * eta)
    bits = bytes_to_bits(data)
    f = []
    for i in range(256):
        x = sum(bits[2*i*eta+j] for j in range(eta))
        y = sum(bits[2*i*eta+eta+j] for j in range(eta))
        z = x - y
        f.append(z)
    return f



# K-PKE

def kpke_keygen(seed: bytes=None) -> Tuple[bytes, bytes]:
	d = os.urandom(32) if seed is None else seed
	ghash = mlkem_hash_G(d)
	rho, sigma = ghash[:32], ghash[32:]

	ahat = []
	for i in range(K):
		row = []
		for j in range(K):
			row.append(sample_ntt(mlkem_xof(rho, i, j)))
		ahat.append(row)
	
	shat = [
		ntt(sample_poly_cbd(ETA1, mlkem_prf(ETA1, sigma, i)))
		for i in range(K)
	]
	ehat = [
		ntt(sample_poly_cbd(ETA1, mlkem_prf(ETA1, sigma, i+K)))
		for i in range(K)
	]
	that = [reduce(ntt_add, [ntt_mul(ahat[j][i], shat[j])for j in range(K)] + [ehat[i]])for i in range(K)]
	ek_pke = b"".join(byte_encode(12, s) for s in that) + rho
	dk_pke = b"".join(byte_encode(12, s) for s in shat)
	return ek_pke, dk_pke


def kpke_encrypt(ek_pke: bytes, m: bytes, r: bytes) -> bytes:
	that = [byte_decode(12, ek_pke[i*128*K:(i+1)*128*K]) for i in range(K)]
	rho = ek_pke[-32:]

	ahat = []
	for i in range(K):
		row = []
		for j in range(K):
			row.append(sample_ntt(mlkem_xof(rho, i, j)))
		ahat.append(row)
	
	rhat = [
		ntt(sample_poly_cbd(ETA1, mlkem_prf(ETA1, r, i)))
		for i in range(K)
	]
	e1 = [
		sample_poly_cbd(ETA2, mlkem_prf(ETA2, r, i+K))
		for i in range(K)
	]
	e2 = sample_poly_cbd(ETA2, mlkem_prf(ETA2, r, 2*K))

	u = [poly256_add(ntt_inv(reduce(ntt_add, [ntt_mul(ahat[i][j], rhat[j]) for j in range(K)])), e1[i]) for i in range(K)]
	
	mu = decompress(1, byte_decode(1, m))
	v = poly256_add(ntt_inv(reduce(ntt_add, [
		ntt_mul(that[i], rhat[i])
		for i in range(K)
	])), poly256_add(e2, mu))

	c1 = b"".join(byte_encode(DU, compress(DU, u[i])) for i in range(K))
	c2 = byte_encode(DV, compress(DV, v))
	return c1 + c2


def kpke_decrypt(dk_pke: bytes, c: bytes) -> bytes:
	c1 = c[:32*DU*K]
	c2 = c[32*DU*K:]
	u = [
		decompress(DU, byte_decode(DU, c1[i*32*DU:(i+1)*32*DU]))
		for i in range(K)
	]
	v = decompress(DV, byte_decode(DV, c2))
	shat = [byte_decode(12, dk_pke[i*384:(i+1)*384]) for i in range(K)]

	w = poly256_sub(v, ntt_inv(reduce(ntt_add, [
		ntt_mul(shat[i], ntt(u[i]))
		for i in range(K)
	])))
	m = byte_encode(1, compress(1, w))
	return m


def mlkem_keygen(seed1=None, seed2=None):
	z = os.urandom(32) if seed1 is None else seed1
	ek_pke, dk_pke = kpke_keygen(seed2)
	ek = ek_pke
	dk = dk_pke + ek + mlkem_hash_H(ek) + z
	return ek, dk


def mlkem_encaps(ek: bytes, seed=None) -> Tuple[bytes, bytes]:
	
	m = os.urandom(32) if seed is None else seed
	ghash = mlkem_hash_G(m + mlkem_hash_H(ek))
	k = ghash[:32]
	r = ghash[32:]
	c = kpke_encrypt(ek, m, r)
	return k, c


def mlkem_decaps(c: bytes, dk: bytes) -> bytes:
	
	dk_pke = dk[:384*K]
	ek_pke = dk[384*K : 768*K + 32]
	h = dk[768*K + 32 : 768*K + 64]
	z = dk[768*K + 64 : 768*K + 96]
	mdash = kpke_decrypt(dk_pke, c)
	ghash = mlkem_hash_G(mdash + h)
	kdash = ghash[:32]
	rdash = ghash[32:]

	kbar = mlkem_hash_J(z + c)
	cdash = kpke_encrypt(ek_pke, mdash, rdash)
	if cdash != c:
		
		return kbar
	return kdash


if __name__ == "__main__":
	a = list(range(256))
	b = list(range(1024, 1024+256))

	ntt_res = ntt_inv(ntt_add(ntt(a), ntt(b)))
	poly_res = poly256_add(a, b)

	assert(ntt_res == poly_res)

	ntt_prod = ntt_inv(ntt_mul(ntt(a), ntt(b)))
	


	ek_pke, dk_pke = kpke_keygen(b"SEED"*8)

	msg = b"Je vous envoie un super message."
    print("message = ", msg)
	ct = kpke_encrypt(ek_pke, msg, b"RAND"*8)
	pt = kpke_decrypt(dk_pke, ct)
	print("dechiffre = ",pt)
	assert(pt == msg)


	ek, dk = mlkem_keygen()
	k1, c = mlkem_encaps(ek)
	print("encapsulé:", k1.hex())

	k2 = mlkem_decaps(c, dk)
	print("décapsulé:", k2.hex())

	assert(k1 == k2)
