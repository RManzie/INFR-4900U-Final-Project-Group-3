# Blockchain Final Project
# Project Group 3
# Shiv Mangal (100550777)
# Ryan Manzie (100743508)
# Blake Whiting (100743587)

# LibraryBlock Library Blockchain System
# Stores Book Checkout Information on the Blockchain 

# Proof of Work Blockchain

# --- Dependencies ---
# Requires pip installs of hashlib, cryptography, flask, json

import json
import hashlib
from uuid import uuid4
from flask import Flask, render_template, jsonify, request
from time import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import webbrowser

# Library Chain Object
class LibraryBlock(object):

    diffLevel = "000"
    
    def __init__(self):
        self.chain = []
        self.currentTransaction = []
        genHash = self.blockHash("")
        self.appendBlock(prevBlockHash = genHash,nonce = self.proofOfWork(0, genHash, []))

    # Hashes the blocks
    def blockHash(self,block):
        blockEncoder = json.dumps(block, sort_keys=True).encode()
        # SHA512 Hashing used for the strongest security
        return hashlib.sha512(blockEncoder).hexdigest()

    def validateProof(self,index, prevBlockHash,transactions,nonce):
        data = f'{index},{prevBlockHash},{transactions},{nonce}'.encode()
        hashData = hashlib.sha512(data).hexdigest()
        return hashData[:len(self.diffLevel)] == self.diffLevel

    # Proof of Work Method
    def proofOfWork(self,index, prevBlockHash, transactions):
        nonce=0
        while self.validateProof(index, prevBlockHash, transactions, nonce) is False:
            nonce+=1

        print(f"Nonce: {nonce}")
        return nonce
    # Append block to the chain
    def appendBlock(self,nonce, prevBlockHash):
        block ={
            'Index': len(self.chain),
            'Transactions':self.currentTransaction,
            'Timestamp': time(),
            'Nonce' : nonce,
            'Previous Block Hash': prevBlockHash
        }
        self.currentTransaction = []
        self.chain.append(block)
        return block

    # Add a new transaction to the chain
    def addTransaction(self, bookName, bookNum, memName, memNum, inout, pubKey):
        self.currentTransaction.append({
        'Book Title':bookName,
        'Book Number':bookNum,
        'Member Name':memName,
        'Member ID:':memNum, 
        'Transaction Type:':inout,
        'Public Key:':pubKey})
        return self.lastBlock['Index']+1

    @property
    def lastBlock(self):
        return self.chain[-1]

#Initialize LibraryBlock object
libBlock = LibraryBlock()

#Initialize flask instance
webapp = Flask(__name__)
nodeIdentifier = str(uuid4()).replace('-',"")
print(f"Running Node: {nodeIdentifier}")

# Flask backend for Web Pages

# Home Page
@webapp.route('/home')
def index():
    print("Home Page")
    return render_template("index.html", name="home")

# Page for Reading the Chain
@webapp.route('/read', methods=['GET'])
def Read():
    print("Reading Blockchain")
    data = {'chain': libBlock.chain,'length': "Blocks: "+ str(len(libBlock.chain))}
    return render_template("read.html", data=data)

# Key Pair Generation Page
@webapp.route('/generate', methods=['GET', 'POST'])
def keyPair():
    print("Keypair Creation Page")
    if request.method == "POST":
        password = request.form.get("privatepass")
        password = password.encode()
        print(password)
        priKeyGen = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Generating Private Key
        priKey = priKeyGen.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )

        # Generating Public Key
        pubKey = priKeyGen.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Prepares the Keys for display
        pubKey = pubKey.decode()
        pubKey = pubKey.replace("-----BEGIN PUBLIC KEY-----", "")
        pubKey = pubKey.replace("-----END PUBLIC KEY-----", "")
        priKey = priKey.decode()
        priKey = priKey.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
        priKey = priKey.replace("-----END ENCRYPTED PRIVATE KEY-----", "")
        # Display the keys on the web page
        return render_template("generate.html", pub=pubKey, pri = priKey)

    return render_template("generate.html", name="generate")

# Checkout/Checkin page for books
@webapp.route('/checkout', methods=['GET', 'POST'])
def Checkout():
    print("Book Checkout Page")
    if request.method == "POST":
        # Gets Data From Page
        bookName = request.form.get("bookname")
        bookNum = request.form.get("booknum")
        memName = request.form.get("memname")
        userID = request.form.get("IDnum")
        pubKey = request.form.get('key')
        inout = request.form.get('check-in-out')
        print(f"Book Name: {bookName}")
        print(f"Book Number: {bookNum}")
        print(f"Member Name: {memName}")
        print(f"Member ID Number: {userID}")
        print(f"Type: {inout}")
        newTransactions(bookName, bookNum, memName, userID, inout, pubKey,)
    return render_template("checkout.html", name="checkout")

# New Book Checkout   
@webapp.route('/checkout/new', methods=['POST'])
def newTransactions(bookName, bookNum, memName, userID, inout, pubKey):
    libBlock.addTransaction(bookName, bookNum, memName, userID, inout, pubKey)
    print("Adding Transaction to Blockchain")
    lastBlockHash = libBlock.blockHash(libBlock.lastBlock)
    index = len(libBlock.chain)
    nonce = libBlock.proofOfWork(index,lastBlockHash,libBlock.currentTransaction)
    block = libBlock.appendBlock(nonce,lastBlockHash)
    response = {
        'Message': f'Transaction added to block {index}',
        'Hash of Previous Block': block['Previous Block Hash'],
        'Nonce':block['Nonce'],
        'Transaction':block['Transactions']}
    return (jsonify(response), 200)

if __name__=='__main__':
    # Launches Web Browser and Starts the LibraryBlock Web App on Port 80
    webbrowser.open("http://127.0.0.1/home") 
    webapp.run(host='0.0.0.0', port=80)
    
