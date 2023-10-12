# NaClProfile.py
# An encrypted version of the Profile class provided by the Profile.py module
# 
# for ICS 32
# by Mark S. Baldwin

from email import message
import json, time, os
from pathlib import Path
from turtle import update

# TODO: Install the pynacl library so that the following modules are available
# to your program.
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

# TODO: Import the Profile and Post classes
from Profile import Post, Profile, DsuFileError, DsuProfileError
# TODO: Import the NaClDSEncoder module
from NaClDSEncoder import NaClDSEncoder
# TODO: Subclass the Profile class

class NaClProfile(Profile):
    def __init__(self):
        """
        TODO: Complete the initializer method. Your initializer should create the follow three 
        public data attributes:

        public_key:str
        private_key:str
        keypair:str

        Whether you include them in your parameter list is up to you. Your decision will frame 
        how you expect your class to be used though, so think it through.
        """
        Profile.__init__(self, '168.235.86.101','celsius', 'livefit')
        # self.encoder = NaClDSEncoder() 
        self.public_key:str
        self.private_key:str
        self.keypair:str
        self._posts = []
        # self.box = None

    def generate_keypair(self) -> str:
        """
        Generates a new public encryption key using NaClDSEncoder.

        TODO: Complete the generate_keypair method.

        This method should use the NaClDSEncoder module to generate a new keypair and populate
        the public data attributes created in the initializer.

        :return: str    
        """
        encoder = NaClDSEncoder()
        encoder.generate()
        self.public_key = encoder.public_key 
        self.private_key = encoder.private_key 
        self.keypair = encoder.keypair
        self.pubReceive = None
        # self.box = encoder.create_box(encoder.encode_private_key(self.private_key), encoder.encode_public_key(self.public_key))

        return self.keypair

    def import_keypair(self, keypair: str):
        """
        Imports an existing keypair. Useful when keeping encryption keys in a location other than the
        dsu file created by this class.

        TODO: Complete the import_keypair method.

        This method should use the keypair parameter to populate the public data attributes created by
        the initializer. 
        
        NOTE: you can determine how to split a keypair by comparing the associated data attributes generated
        by the NaClDSEncoder
        """

        self.keypair = keypair
        x = keypair.find('=')
        if x != 43 and len(keypair[:x-1]) != 44:
            self.public_key = None
            self.private_key = None
            self.keypair = None
        else:
            self.public_key = keypair[:x+1]
            self.private_key = keypair[x+1:]
    
        # self.box = self.encoder.create_box(self.encoder.encode_private_key(self.private_key), self.encoder.encode_public_key(self.public_key))

    """
    TODO: Override the add_post method to encrypt post entries.
    Before a post is added to the profile, it should be encrypted. Remember to take advantage of the
    code that is already written in the parent class.

    NOTE: To call the method you are overriding as it exists in the parent class, you can use the built-in super keyword:
    
    super().add_post(...)
    """
    def boxThing(self, pub, priv):
        encoder = NaClDSEncoder
        pubObject = encoder.encode_public_key(pub)
        privObject = encoder.encode_private_key(priv)
        box = encoder.create_box(privObject, pubObject)
        return box
    def encrypt(self, pub, priv, msg):
        encoder = NaClDSEncoder
        box = self.boxThing(pub,priv)
        encrypted = encoder.encrypt_message(box, msg)
        return encrypted
    def decrypt(self, pub, priv, msg):
        box = self.boxThing(pub,priv)
        encoder = NaClDSEncoder
        decrypted = encoder.decrypt_message(box,msg)
        return decrypted

    def add_post(self, post: Post) -> None :
        encoder = NaClDSEncoder()
        msg = post.get_entry()
        pubObject = encoder.encode_public_key(self.public_key)
        privObject = encoder.encode_private_key(self.private_key)
        box = encoder.create_box(privObject, pubObject)
        encrypted = encoder.encrypt_message(box, msg)
        newPost = Post(encrypted, post.get_time())
        self._posts.append(newPost)


    """
    TODO: Override the get_posts method to decrypt post entries.

    Since posts will be encrypted when the add_post method is used, you will need to ensure they are 
    decrypted before returning them to the calling code.

    :return: Post
    
    NOTE: To call the method you are overriding as it exists in the parent class you can use the built-in super keyword:
    super().get_posts()
    """
    def get_posts(self) -> list[Post] :
        
        posts = self._posts
        updatedPost = []
        for post in posts:
            encoder = NaClDSEncoder
            pubObject = encoder.encode_public_key(encoder, self.public_key)
            privObject = encoder.encode_private_key(encoder, self.private_key)
            box = encoder.create_box(encoder, privObject, pubObject)
            decrypted = encoder.decrypt_message(encoder, box, post.get_entry())
            newPost = Post(decrypted, post.get_time())
            updatedPost.append(newPost)
    
        return updatedPost
    """
    TODO: Override the load_profile method to add support for storing a keypair.

    Since the DS Server is now making use of encryption keys rather than username/password attributes, you will 
    need to add support for storing a keypair in a dsu file. The best way to do this is to override the 
    load_profile module and add any new attributes you wish to support.

    NOTE: The Profile class implementation of load_profile contains everything you need to complete this TODO.
     Just copy the code here and add support for your new attributes.
    """
    def load_profile(self, path: str) -> None:
        p = Path(path)
        # {"join": {"username": "ohhimark","password": "password123","token":"my_public_key"}}

        if os.path.exists(p) and p.suffix == '.dsu':
            try:
                f = open(p, 'r')
                obj = json.load(f)
                self.import_keypair(obj['keypair'])
                self.username = obj['username']
                self.password = obj['password']
                self.dsuserver = obj['dsuserver']
                self.bio = obj['bio']
                self.keypair = obj['keypair']
                for post_obj in obj['_posts']:
                    post = Post(post_obj['entry'], post_obj['timestamp'])
                    self._posts.append(post)
                f.close()
            except Exception as ex:
                raise DsuProfileError(ex)
        else:
            raise DsuFileError()

    def encrypt_entry(self, entry:str, public_key:str) -> bytes:
        """
        Used to encrypt messages using a 3rd party public key, such as the one that
        the DS server provides.
        
        TODO: Complete the encrypt_entry method.

        NOTE: A good design approach might be to create private encrypt and decrypt methods that your add_post, 
        get_posts and this method can call.
        
        :return: bytes 
        """
        encoder = NaClDSEncoder
        pubObject = encoder.encode_public_key(public_key)
        privObject = encoder.encode_private_key(self.private_key)
        box = encoder.create_box(privObject, pubObject)
        encrypted = encoder.encrypt_message(box, entry)
        return encrypted


# from pathlib import Path 
# a = Path('C:\Python310\ICS 32\ASSIGNMENTS\ASSIGNMENT 2\\test.dsu')
# print(a.exists())

'''
np = NaClProfile()
kp = np.generate_keypair()
print(np.public_key)
print(np.private_key)
print(np.keypair)

# Test encryption with 3rd party public key
ds_pubkey = "jIqYIh2EDibk84rTp0yJcghTPxMWjtrt5NW4yPZk3Cw="
ee = np.encrypt_entry("Encrypted Message for DS Server", ds_pubkey)
print(ee)

# Add a post to the profile and check that it is decrypted.
np.add_post(Post("Hello Salted World!"))
p_list = np.get_posts()
print(p_list[0].get_entry())

# Save the profile
np.save_profile('C:\Python310\ICS 32\ASSIGNMENTS\ASSIGNMENT 2\\test.dsu')

print("Open DSU file to check if message is encrypted.")
input("Press Enter to Continue")

# Create a new NaClProfile object and load the dsu file.
np2 = NaClProfile()
np2.load_profile('C:\Python310\ICS 32\ASSIGNMENTS\ASSIGNMENT 2\\test.dsu')
# Import the keys
np2.import_keypair(kp)

# Verify the post decrypts properly
p_list = np2.get_posts()
print(p_list[0].get_entry())
'''