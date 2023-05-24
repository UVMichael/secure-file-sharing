package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")

	"errors"

	// Optional.
	_ "strconv"
)

// CONSTANTs
const SALT_SIZE int = 8         // in bytes
const PASS_KEY_SIZE uint32 = 16 // in bytes
const IV_LEN int = 16           // in bytes
const CHUNKSIZE = 512          // in bytes

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Salt                []byte       // Randomly generated salt
	Username            string       //string representing username
	Hmac_Sum            []byte       // MAC on encrypted user data
	Encrypted_User_Data []byte       // projected user data stored in this struct
	private_user_data   Private_User // NOTE: not capitalized so it wont be serialized with Marshal
}

// All private user data is stored within this struct
// This struct is encrypted+MAC before being serialized into datastore
type Private_User struct {
	Private_Key         userlib.PKEDecKey
	Private_signing_key userlib.DSSignKey
	// ... more fields to add
}

// File structs contain all information relating to a file
type File struct {
	Enc_file  []byte
	priv_file priv_File
	MAC_hash  []byte
}
type priv_File struct {
	Start      uuid.UUID
	End        uuid.UUID
	Share_list []share_element //share_list<username, invt location, invt sym_key>
}
type share_element struct {
	Signature       []byte
	EncShareElement []byte
	priv_share      priv_share_element
}
type priv_share_element struct {
	Username      string
	Invt_location uuid.UUID
	Sym_invt_key  []byte
}

type Chunk struct {
	Enc_priv   []byte
	priv_chunk priv_Chunk // unencrypted private data stored here, it is not marshalled and stored
	MAC_hash   []byte
}
type priv_Chunk struct {
	Data_loc       uuid.UUID
	data		[]byte
	MAC_ondata	[]byte
	Next_chunk uuid.UUID
}

// Invitations are the way users access Files
//
//		priv invitation are symmetrically encrypted by a key
//	 publically encrypted for the invitation's owner
type Invitation struct {
	Pub_enc_access []byte
	access         invt_Access // populated by decrypted Pub_enc_sym_key
	Enc_invt       []byte
	priv_invt      priv_Invitation
	Signature      []byte
}
type invt_Access struct {
	Priv_sym_invt_key []byte
	Owner_name        string
	Parent_name       string
}

type priv_Invitation struct {
	File_owner         bool
	Parent_ptr         uuid.UUID // this is for non-owners sharing
	File_ptr           uuid.UUID
	File_ptr_signature []byte //maybe remove
	File_sym_key       []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	//check username not empty
	if username == "" {
		//userlib.DebugMsg("user with empty name created")
		return nil, errors.New(strings.ToTitle("Username field empty"))
	}

	//check if user in Keystore
	_, found := userlib.KeystoreGet(username)
	//if there is a user with this username already
	if found {
		//userlib.DebugMsg("tried to create duplicate user")
		return nil, errors.New(strings.ToTitle("tried to create duplicate user"))
	}

	//unique user add into keystore
	//userlib.DebugMsg("adding user to key store")
	//generate user private public key
	publicKey, privateKey, KeyGenErr := userlib.PKEKeyGen()
	if KeyGenErr != nil {
		return nil, errors.New(strings.ToTitle("error in RSA keyGen"))
	}
	KeystoreSetErr := userlib.KeystoreSet(username, publicKey)
	//error check keystore set
	if KeystoreSetErr != nil {
		return nil, errors.New(strings.ToTitle("failed keystore set"))
	}

	//userlib.DebugMsg("creating the signing verification key for user")
	DSSignKey, DSVerifyKey, DSErr := userlib.DSKeyGen()
	if DSErr != nil {
		return nil, errors.New(strings.ToTitle("error in RSA SignkeyGen"))
	}
	KeystoreSetErr = userlib.KeystoreSet(username+"verification", DSVerifyKey)
	//error check keystore set
	if KeystoreSetErr != nil {
		return nil, errors.New(strings.ToTitle("failed keystore set"))
	}

	//encrypt userdata
	salt := userlib.RandomBytes(SALT_SIZE)
	encKey, macKey, genErr := generateMacHashKeys(salt, password, username)
	if genErr != nil {
		//userlib.DebugMsg("failed to gen mac and hash keys")
		return nil, errors.New(strings.ToTitle("failed to gen mac and hash keys"))
	}

	//build userData for new user.
	var userInfo User
	//gen private data
	var privateData Private_User
	privateData.Private_Key = privateKey
	privateData.Private_signing_key = DSSignKey

	userInfo.private_user_data = privateData

	//encrypt private data
	privateDataBytes, PMarshalErr := json.Marshal(privateData)
	if PMarshalErr != nil {
		//userlib.DebugMsg("failed to marshal private data")
		return nil, errors.New(strings.ToTitle("failed to marshal private data"))
	}
	encPrivateData := userlib.SymEnc(encKey, userlib.RandomBytes(IV_LEN), privateDataBytes)
	//gen Hmac
	hmac, HMACerr := userlib.HMACEval(macKey, encPrivateData)
	if HMACerr != nil {
		return nil, errors.New(strings.ToTitle("failed to generate mac key"))
	}
	//set hmac
	userInfo.Hmac_Sum = hmac
	userInfo.Username = username
	userInfo.Salt = salt
	userInfo.Encrypted_User_Data = encPrivateData

	hash := userlib.Hash([]byte(username))
	deterministicUUID, UUIDErr := uuid.FromBytes(hash[:16])
	if UUIDErr != nil {
		return nil, errors.New("UUID could not be generated")
	}
	//serialize the data into byte slices
	userBytes, marshalErr := json.Marshal(userInfo)
	if marshalErr != nil {
		return nil, errors.New("could not marshal data")
	}
	//userlib.DebugMsg("writing initial user to DataStore")
	userlib.DatastoreSet(deterministicUUID, userBytes)

	return &userInfo, nil
	//add user to data store
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	//Creates a UUID deterministically, from a sequence of bytes.
	//userlib.DebugMsg("Creating Hash and UUID From Username")
	hash := userlib.Hash([]byte(username))
	deterministicUUID, UUIDerr := uuid.FromBytes(hash[:16])
	if UUIDerr != nil {
		//userlib.DebugMsg("UUID failed")
		return nil, errors.New(strings.ToTitle("An error occurred while generating a UUID: "))
	}
	//userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Access datastore
	//userlib.DebugMsg("Accessing Data store and searching UUID")
	dataJSON, ok := userlib.DatastoreGet(deterministicUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("Userdata not found at UUID"))
	}

	//userlib.DebugMsg("Create userData pointer to return")
	var userData User
	//userlib.DebugMsg("Unmarshal Data")
	unmarshalErr := json.Unmarshal(dataJSON, &userData)
	if unmarshalErr != nil {
		return nil, errors.New(strings.ToTitle("could not unmarshal Data"))
	}
	//userlib.DebugMsg("Decrypt private portion of userData")
	encKey, macKey, genErr := generateMacHashKeys(userData.Salt, password, username)
	if genErr != nil {
		return nil, errors.New(strings.ToTitle("failed to gen mac and hash keys"))
	}
	//userlib.DebugMsg("Check HMac")
	hmac, HMACerr := userlib.HMACEval(macKey, userData.Encrypted_User_Data)
	if HMACerr != nil {
		return nil, errors.New(strings.ToTitle("failed to generate mac key"))
	}
	valid := userlib.HMACEqual(userData.Hmac_Sum, hmac)
	if !valid {
		return nil, errors.New(strings.ToTitle("new and old Hmac sum unequal"))
	}
	//userlib.DebugMsg("Decrypt private data")
	PrivateData := userlib.SymDec(encKey, userData.Encrypted_User_Data)
	//userlib.DebugMsg("Unmarshal private data and place into user struct")
	unmarshalErr = json.Unmarshal(PrivateData, &userData.private_user_data)
	if unmarshalErr != nil {
		return nil, errors.New(strings.ToTitle("could not unmarshal private user Data"))
	}

	return &userData, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	if userdata == nil {
		return errors.New(strings.ToTitle("nil user data"))
	}
	//generate location for the file accepted invite
	//userlib.DebugMsg("generate UUID")
	storageKey, err := getInvtUUID(filename, userdata.Username)
	if err != nil {
		return errors.New(strings.ToTitle("failed to generate storage key"))
	}

	//check if file already exists and need to overwrite
	foundInvitation, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		//userlib.DebugMsg("file for user with this user does not exist creating a new one")
		//userlib.DebugMsg("creating a new acceptedInvite struct")
		var invt Invitation
		invt.priv_invt.File_owner = true

		//userlib.DebugMsg("generating random UUID for file struct")
		invt.priv_invt.File_ptr = getRandomValidUUID()

		//userlib.DebugMsg(("creating file"))
		var file File
		//userlib.DebugMsg(("creating symetric key for the file and hash key"))
		invt.priv_invt.File_sym_key = userlib.RandomBytes(16)
		file_mac_key, mackeygenErr := userlib.HashKDF(invt.priv_invt.File_sym_key, []byte("mac"))
		if mackeygenErr != nil {
			return errors.New(strings.ToTitle("failed to create file mac key"))
		}

		err = putContentInChunks(content, &file, &invt, file_mac_key[:16])
		if err != nil {
			return err
		}

		//userlib.DebugMsg("populate invitation fields + store it")
		invt.access.Priv_sym_invt_key = userlib.RandomBytes(16)
		invt.access.Parent_name = userdata.Username
		invt.access.Owner_name = userdata.Username

		// Write invitation as recipient being ourselves
		err = writeInvitation(userdata, storageKey, userdata.Username, &invt)
		if err != nil {
			return err
		}

		//userlib.DebugMsg("populate file fields + store it")
		err = writeFile(&file, file_mac_key, &invt)
		if err != nil {
			return err
		}

		// debug:
		//userlib.DebugMsg(" IN STORE File start %s, File end %s", file.priv_file.Start, file.priv_file.End)
		//userlib.DebugMsg("this is the length %s", len(content))
	} else {
		//userlib.DebugMsg("entering case file invitation found")
		file, invt, file_mac_key, getFErr := getFileFromInvt(userdata, foundInvitation)
		if getFErr != nil {
			return getFErr
		}

		//userlib.DebugMsg("clear file chunk pointers ")
		var chunk Chunk
		curr := file.priv_file.Start

		for curr != uuid.Nil {
			//userlib.DebugMsg("get chunk")
			//userlib.DebugMsg("the UUID STORING THE CHNK IS %v IN OVERWRITE STORE", curr)
			chunkBytes, found := userlib.DatastoreGet(curr)
			if !found {
				return errors.New(strings.ToTitle("chunk does not exist "))
			}
			errChunk := extractChunk(chunkBytes, &chunk, invt.priv_invt.File_sym_key, file_mac_key[:16], true)
			if errChunk != nil {
				return errChunk
			}
			userlib.DatastoreDelete(curr)
			curr = chunk.priv_chunk.Next_chunk
		}

		err = putContentInChunks(content, &file, &invt, file_mac_key[:16])
		if err != nil {
			return err
		}

		err = writeFile(&file, file_mac_key, &invt)
		if err != nil {
			return err
		}
		// debug:

		//userlib.DebugMsg("this is the length %s", len(content))
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Retrieve all necessary metadata about file (file, invt, file_mac_key)
	if userdata == nil {
		return errors.New(strings.ToTitle("nil user data"))
	}
	if len(content) == 0 {
		return nil;
	}
	storageKey, err := getInvtUUID(filename, userdata.Username)
	if err != nil {
		return errors.New(strings.ToTitle("failed to generate storage key"))
	}
	//userlib.DebugMsg("check if invt exists - in append")
	foundInvitation, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New(strings.ToTitle("file does not exist for user"))
	}
	//userlib.DebugMsg("getting file")
	file, invt, file_mac_key, getFErr := getFileFromInvt(userdata, foundInvitation)
	if getFErr != nil {
		return getFErr
	}
	// Goto last chunk of file
	//userlib.DebugMsg("getting last chunk")
	chunkBytes, found := userlib.DatastoreGet(file.priv_file.End)
	if !found {
		return errors.New(strings.ToTitle("last chunk not found"))
	}
	var currEndChunk Chunk
	errChunk := extractChunk(chunkBytes, &currEndChunk, invt.priv_invt.File_sym_key, file_mac_key[:16], false)
	if errChunk != nil {
		return errChunk
	}

	// Change pointer of last chunk
	currEndChunk.priv_chunk.Next_chunk = getRandomValidUUID();
	err = writeIndivdualChunk(&currEndChunk, file.priv_file.End, &invt, file_mac_key, false)
	if err != nil {
		return err
	}

	// Extend file by adding more chunks
	errWr := WriteChunks(content, &file, &invt, file_mac_key[:16], currEndChunk.priv_chunk.Next_chunk)
	if errWr != nil {
		return errWr
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//userlib.DebugMsg("generate UUID for file invt")

	if userdata == nil {
		return nil, errors.New(strings.ToTitle("nil user data"))
	}
	storageKey, err := getInvtUUID(filename, userdata.Username)
	if err != nil {
		return nil, errors.New(strings.ToTitle("failed to generate storage key"))
	}
	//userlib.DebugMsg("check if invt exists - in load")
	foundInvitation, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file does not exist for user"))
	}
	file, invt, file_mac_key, getFErr := getFileFromInvt(userdata, foundInvitation)
	if getFErr != nil {
		return nil, getFErr
	}
	//userlib.DebugMsg("get data from chunks")
	var rawData []byte
	var chunk Chunk
	curr := file.priv_file.Start

	for curr != uuid.Nil {
		chunkBytes, found := userlib.DatastoreGet(curr)
		if !found {
			return nil, errors.New(strings.ToTitle("chunk does not exist "))
		}
		errChunk := extractChunk(chunkBytes, &chunk, invt.priv_invt.File_sym_key, file_mac_key[:16], true)
		if errChunk != nil {
			return nil, errChunk
		}
		//userlib.DebugMsg("appending chunk data to raw data")
		// //userlib.DebugMsg("appended chunk \" %v \" to  to raw data \" %v \"", privChunkBytes, rawData)
		rawData = append(rawData, chunk.priv_chunk.data...)
		// //userlib.DebugMsg(" curr raw data \" %v \"", rawData)
		curr = chunk.priv_chunk.Next_chunk
	}
	return rawData, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	if userdata == nil {
		return uuid.Nil, errors.New(strings.ToTitle("nil user data"))
	}
	//userlib.DebugMsg("search for filename in user's namespace")
	storageKey, err := getInvtUUID(filename, userdata.Username)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("failed to generate storage key"))
	}
	//userlib.DebugMsg("check if invt exists- in create invt")
	foundInvitation, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("Cannot share non-existant file"))
	}
	//userlib.DebugMsg("check user has access to the file")
	//_, invt, _, GFFIerr := getFileFromInvt(userdata, foundInvitation)
	//if GFFIerr != nil {
	//	return uuid.Nil, errors.New(strings.ToTitle("user does not have acces to share file"))
	//}

	// use our personal invitation to pass on the access key and other restricted values
	our_invt, err := extractInvite(userdata, foundInvitation)
	if err != nil {
		return uuid.Nil, err
	}

	//build new invitation
	var newUserInvite Invitation
	newUserInvite.priv_invt.File_owner = false

	// Create the compressed tree structure
	if our_invt.priv_invt.File_owner {
		newUserInvite.priv_invt.File_sym_key = our_invt.priv_invt.File_sym_key
		newUserInvite.priv_invt.File_ptr = our_invt.priv_invt.File_ptr
		newUserInvite.priv_invt.Parent_ptr = storageKey
	} else {
		if our_invt.priv_invt.File_ptr != uuid.Nil { // A CHILD
			newUserInvite.priv_invt.Parent_ptr = storageKey
		} else { //A Grand CHILD
			newUserInvite.priv_invt.Parent_ptr = our_invt.priv_invt.Parent_ptr
		}
	}

	newUserInvite.access.Owner_name = our_invt.access.Owner_name
	newUserInvite.access.Priv_sym_invt_key = our_invt.access.Priv_sym_invt_key
	newUserInvite.access.Parent_name = userdata.Username //FIXME WRONG LOACATIOn
	// I think its right. because the invitation giver signs the child's invitation
	// and the giver is the direct parent. We use this field to get the key for that sign
	// check

	location := getRandomValidUUID()
	err = writeInvitation(userdata, location, recipientUsername, &newUserInvite)
	if err != nil {
		return uuid.Nil, err
	}

	//FIXME ADD TO PENDING LIST
	return location, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// get invitation form invitation pointer
	if userdata == nil {
		return errors.New(strings.ToTitle("nil user data"))
	}
	foundInvitation, found := userlib.DatastoreGet(invitationPtr)
	if !found {
		return errors.New(strings.ToTitle("failed to generate storage key"))
	}
	invt, invtErr := extractInvite(userdata, foundInvitation)
	if invtErr != nil {
		return invtErr
	}
	// check with sender username verification
	if senderUsername != invt.access.Parent_name {
		return errors.New(strings.ToTitle("missmatch sender and parent"))
	}
	// re write all data to the uuid comprised of filename+ username
	storageKey, err := getInvtUUID(filename, userdata.Username)
	if err != nil {
		return errors.New(strings.ToTitle("failed to generate storage key"))
	}
	userlib.DatastoreSet(storageKey, foundInvitation)
	//delete old Datastore entry of invitation
	userlib.DatastoreDelete(invitationPtr)

	// access file and update the share list to confirm the acceptance on sender's side
	//FIXME ADD TO SHARE LIST
	if invt.priv_invt.File_ptr != uuid.Nil {
		pubKey, found := userlib.KeystoreGet(senderUsername)
		if !found {
			return errors.New(strings.ToTitle("sender not found"))
		}
		var newElem share_element
		// Create our share element
		newElem.priv_share.Invt_location = storageKey
		newElem.priv_share.Sym_invt_key = invt.access.Priv_sym_invt_key
		newElem.priv_share.Username = userdata.Username

		privShareBytes, err := json.Marshal(newElem.priv_share)
		if err != nil {
			return errors.New(strings.ToTitle("couldn't marshal priv share Data in AcceptInvt"))
		}

		newElem.EncShareElement, err = userlib.PKEEnc(pubKey, privShareBytes)
		if err != nil {
			return errors.New(strings.ToTitle("PKE failed"))
		}

		newElem.Signature, err = userlib.DSSign(userdata.private_user_data.Private_signing_key, newElem.EncShareElement)
		if err != nil {
			return errors.New(strings.ToTitle("sender not found"))
		}
		userlib.DebugMsg("ACCEPT")
		userlib.DebugMsg("Signature of %v is %v", userdata.Username, userlib.Hash(newElem.Signature))
		userlib.DebugMsg("EncBytes of %v is %v", userdata.Username, userlib.Hash(newElem.EncShareElement))
		userlib.DebugMsg("END ACCEPT")
		// Add populated share elem to share list
		file, file_mac_key, err := extractFile(userdata, &invt)
		if err != nil {
			return err
		}
		file.priv_file.Share_list = append(file.priv_file.Share_list, newElem)

		err = writeFile(&file, file_mac_key, &invt)
		if err != nil {
			return err
		}
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Ensure that we are the owner of the file
	userlib.DebugMsg("REVOKE ACCESS")
	if userdata == nil {
		return errors.New(strings.ToTitle("nil user data"))
	}
	//userlib.DebugMsg("GET FILE CONTENTS UNENCRYPED")
	file_content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	//userlib.DebugMsg("FINISHED FILE CONTENTS UNENCRYPED")

	storageKey, err := getInvtUUID(filename, userdata.Username)
	if err != nil {
		return errors.New(strings.ToTitle("failed to generate storage key"))
	}
	foundInvitation, found := userlib.DatastoreGet(storageKey)
	if !found {
		return errors.New(strings.ToTitle("User has not such file in their namespace"))
	}
	ownerInvit, exInErr := extractInvite(userdata, foundInvitation)
	if exInErr != nil {
		return exInErr
	}
	if !ownerInvit.priv_invt.File_owner {
		return errors.New(strings.ToTitle("Trying to revoke as a non user"))
	}

	file, _, exFileErr := extractFile(userdata, &ownerInvit)
	if exFileErr != nil {
		return exFileErr
	}
	var newShareList []share_element

	oldFileLocation := ownerInvit.priv_invt.File_ptr
	newFileLocation := getRandomValidUUID()
	newFileSymKey := userlib.RandomBytes(16)
	// Update Owner's invite
	ownerInvit.priv_invt.File_sym_key = newFileSymKey
	ownerInvit.priv_invt.File_ptr = newFileLocation
	WIErr := writeInvitation(userdata, storageKey, userdata.Username, &ownerInvit)
	if WIErr != nil {
		return errors.New(strings.ToTitle("failed to write owner's invitation"))
	}

	// used to check if we actually revoke anyone
	presize := len(file.priv_file.Share_list)

	// iterate through share list and create new share list without revoked recipient
	for _, shareElem := range file.priv_file.Share_list {
		//decrypt share element
		shareElemBytes, decErr := userlib.PKEDec(userdata.private_user_data.Private_Key, shareElem.EncShareElement)
		if decErr != nil {
			return errors.New(strings.ToTitle("couldn't decrypt shared elem"))
		}
		unmarshalErr := json.Unmarshal(shareElemBytes, &shareElem.priv_share)
		if unmarshalErr != nil {
			return errors.New(strings.ToTitle("could not unmarshal share elem Data"))
		}

		//check if name of revoked user
		if shareElem.priv_share.Username != recipientUsername {
			// get pub verify key
			userlib.DebugMsg("Username to not revoke: %v", shareElem.priv_share.Username)
			pubSignKey, found := userlib.KeystoreGet(shareElem.priv_share.Username + "verification")
			if !found {
				return errors.New(strings.ToTitle("couldn't find a share elems pub sign key"))
			}
			// verify signing key
			userlib.DebugMsg("REVOKE")
			userlib.DebugMsg("Signature of %v is %v", shareElem.priv_share.Username, userlib.Hash(shareElem.Signature))
			userlib.DebugMsg("EncBytes of %v is %v", shareElem.priv_share.Username, userlib.Hash(shareElem.EncShareElement))
			userlib.DebugMsg("END REVOKE")

			err = userlib.DSVerify(pubSignKey, shareElem.EncShareElement, shareElem.Signature)
			if err != nil {
				return errors.New(strings.ToTitle("failed to verify signature"))
			}

			//get the invitation
			foundInvitation, found := userlib.DatastoreGet(shareElem.priv_share.Invt_location)
			if !found {
				return errors.New(strings.ToTitle("foudn no child invitation at the location "))
			}

			var shared_invt Invitation
			unmarshalErr := json.Unmarshal(foundInvitation, &shared_invt)
			if unmarshalErr != nil {
				return errors.New(strings.ToTitle("couldn't unmarshal found invitation Data"))
			}
			//Use key of invitation creator(this user) to check validity
			pubSigKey, found := userlib.KeystoreGet(userdata.Username + "verification")
			if !found {
				return errors.New(strings.ToTitle("no pubsigning  key for user with username found"))
			}

			checkSign := userlib.DSVerify(pubSigKey, append(shared_invt.Enc_invt, shared_invt.Pub_enc_access...), shared_invt.Signature)
			if checkSign != nil {
				return errors.New(strings.ToTitle("signing key verification failed"))
			}
			privInvitationBytes := userlib.SymDec(shareElem.priv_share.Sym_invt_key, shared_invt.Enc_invt)
			unmarshalErr = json.Unmarshal(privInvitationBytes, &shared_invt.priv_invt)
			if unmarshalErr != nil {
				return errors.New(strings.ToTitle("couldn't unmarshal found priv invitation Data"))
			}

			// have the shared invitation
			// modify invitation and write back
			shared_invt.priv_invt.File_sym_key = newFileSymKey
			shared_invt.priv_invt.File_ptr = newFileLocation

			// rewrite access field for write (we cant decrypt but know all the fields bc we owner)
			shared_invt.access.Owner_name = userdata.Username
			shared_invt.access.Parent_name = userdata.Username
			shared_invt.access.Priv_sym_invt_key = shareElem.priv_share.Sym_invt_key

			err = writeInvitation(userdata, shareElem.priv_share.Invt_location, shareElem.priv_share.Username, &shared_invt)
			if err != nil {
				return err
			}

			shareElem.priv_share = priv_share_element{"", uuid.Nil, []byte(nil)} // zero out priv_share field when storing in share list
			newShareList = append(newShareList, shareElem)
		} else {
			// DESTROY RECIPIENTS INVITATION
			userlib.DatastoreDelete(shareElem.priv_share.Invt_location)
		}
	}
	//write file back
	file.priv_file.Share_list = newShareList

	// rederive file_mac_key from new file_sym_key
	new_file_mac_key, err := userlib.HashKDF(ownerInvit.priv_invt.File_sym_key, []byte("mac"))
	if err != nil {
		return errors.New(strings.ToTitle("derivation of mac_key failed in revoke"))
	}

	// Update chunks of file (re-encrypt with new sym and MAC keys)
	//file.priv_file.Start = getRandomValidUUID()
	//WriteChunks(file_content, &file, &ownerInvit, new_file_mac_key, file.priv_file.Start)
	err = putContentInChunks(file_content, &file, &ownerInvit, new_file_mac_key[:16])
	if err != nil {
		return err
	}
	// Copy file into a new UUID location
	err = writeFile(&file, new_file_mac_key[:16], &ownerInvit)
	if err != nil {
		return err
	}

	// iterate through share list and update all invitation structs
	// 	 Update :
	//		file pointer
	//		sym_key
	//		re-sign invitation struct
	//userlib.DebugMsg("Destroy old file ")
	userlib.DatastoreDelete(oldFileLocation)

	userlib.DebugMsg("EXITING REVOKE ACCESS")
	if len(newShareList) == presize {
		return errors.New(strings.ToTitle("file not in revokee name space"))
	}
	return nil
}

// ------------------------------------------------------------
// ------------------------------------------------------------
// --------------------- HELPER FUNCTIONS ---------------------
// ------------------------------------------------------------
// ------------------------------------------------------------

func getInvtUUID(filename string, username string) (uuid.UUID, error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + fmt.Sprint(len(filename)) + username))[:16])
	return storageKey, err
}

// Returns the 'effective invitation' or the top level invitation that has a pointer to the
//
//	file. For children of the owner, this is just their own invitation struct. For children
//	of children, they must first process their sub invitation to gain access to this invt
func getEffectiveInvt(userdata *User, foundInvitation []byte) (Invitation, error) {

	sub_invt, err := extractInvite(userdata, foundInvitation)
	if err != nil {
		return sub_invt, err
	}
	//Part 1 check if need to get parent
	if sub_invt.priv_invt.File_ptr != uuid.Nil {
		return sub_invt, nil
	}
	//get parent

	sym_invitKEY := sub_invt.access.Priv_sym_invt_key
	parentInvtBytes, found := userlib.DatastoreGet(sub_invt.priv_invt.Parent_ptr)
	if !found {
		return sub_invt, errors.New(strings.ToTitle("no parent found"))
	}

	// manually extract invitation using our sub_invt access
	var parent_invt Invitation
	unmarshalErr := json.Unmarshal(parentInvtBytes, &parent_invt)
	if unmarshalErr != nil {
		return parent_invt, errors.New(strings.ToTitle("couldn't unmarshal parent invitation"))
	}

	//Use key of invitation creator to check validity
	pubSigKey, found := userlib.KeystoreGet(sub_invt.access.Owner_name + "verification")
	if !found {
		return parent_invt, errors.New(strings.ToTitle("couldn't find owner's pub signing key"))
	}

	//userlib.DebugMsg(">>> check signature")
	checkSign := userlib.DSVerify(pubSigKey, append(parent_invt.Enc_invt, parent_invt.Pub_enc_access...), parent_invt.Signature)
	if checkSign != nil {
		//userlib.DebugMsg(">>> this child thinks this is the owner: %v", sub_invt.access.Owner_name)
		return parent_invt, errors.New(strings.ToTitle("owner's signing key verification failed"))
	}

	//userlib.DebugMsg(">>> decrypting invitation")
	privInvitationBytes := userlib.SymDec(sym_invitKEY, parent_invt.Enc_invt)

	//userlib.DebugMsg(">>> unmarshal private invitation bytes")
	unmarshalErr = json.Unmarshal(privInvitationBytes, &parent_invt.priv_invt)
	if unmarshalErr != nil {
		return parent_invt, errors.New(strings.ToTitle("couldn't unmarshal found priv invitation Data"))
	}

	return parent_invt, nil
}

func getRandomValidUUID() uuid.UUID {
	//userlib.DebugMsg("entering the super UUID loop")
	var curr_ptr uuid.UUID
	var errUUID error
	for {
		curr_ptr, errUUID = uuid.FromBytes((userlib.RandomBytes(16)))
		_, errGet := userlib.DatastoreGet(curr_ptr)
		if !errGet && errUUID == nil {
			break
		}
		//userlib.DebugMsg("looping...")
	}
	//userlib.DebugMsg("valid file UUID chosen")
	return curr_ptr
}

// Used in storeFile to place content into new chunks and set their start/end pointers
//
//	It uses the keys in invt to encrypt the chunks
func putContentInChunks(content []byte, file *File, invt *Invitation, file_mac_key []byte) error {
	//userlib.DebugMsg(("slicing chunks of input"))
	// Put content into chunks
	curr_UUID := getRandomValidUUID()
	file.priv_file.Start = curr_UUID

	errWr := WriteChunks(content, file, invt, file_mac_key, curr_UUID)
	if errWr != nil {
		return errWr
	}

	//userlib.DebugMsg("IN THE HELPER File start %s, File end %s", file.priv_file.Start, file.priv_file.End)
	return nil
}

// (This helper function is to be deprecated, simply a wrapper for extractFile and fvite)
// Receives raw data from datastore and gets the file and invitation structs for later use
func getFileFromInvt(userdata *User, foundInvitation []byte) (File, Invitation, []byte, error) {
	var file File
	var file_mac_key []byte

	invt, err := getEffectiveInvt(userdata, foundInvitation)
	if err != nil {
		return file, invt, file_mac_key, err
	}
	file, file_mac_key, err = extractFile(userdata, &invt)
	if err != nil {
		return file, invt, file_mac_key, err
	}

	return file, invt, file_mac_key, nil
}

func writeInvitation(userdata *User, storageKey uuid.UUID, recipient string, invt *Invitation) error {
	//userlib.DebugMsg("getting user public symmetric key")
	pubKey, found := userlib.KeystoreGet(recipient)
	if !found {
		return errors.New(strings.ToTitle("no pub key for user with username found"))
	}
	accessBytes, err := json.Marshal(invt.access)
	if err != nil {
		return errors.New(strings.ToTitle("failed to marshal invt access"))
	}
	//userlib.DebugMsg("Public encrypt the sym_invt_key")
	invt.Pub_enc_access, err = userlib.PKEEnc(pubKey, accessBytes)
	if err != nil {
		return errors.New(strings.ToTitle("failed to pub encrypt the invt sym_key"))
	}
	//userlib.DebugMsg("Alice is storing this File Loc: %v", invt.priv_invt.File_ptr)
	privInvtBytes, errInvtMarsh := json.Marshal(invt.priv_invt)
	if errInvtMarsh != nil {
		return errors.New(strings.ToTitle("failed to marshal priv invitation"))
	}
	//userlib.DebugMsg("Encrypt invitation with invt sym key")
	invt.Enc_invt = userlib.SymEnc(invt.access.Priv_sym_invt_key, userlib.RandomBytes(IV_LEN), privInvtBytes)

	invt.Signature, err = userlib.DSSign(userdata.private_user_data.Private_signing_key, append(invt.Enc_invt, invt.Pub_enc_access...))
	if err != nil {
		return errors.New(strings.ToTitle("failed to sign invitation"))
	}
	var invtBytes []byte
	invtBytes, err = json.Marshal(invt)
	if err != nil {
		return errors.New(strings.ToTitle("failed to marshal invitation"))
	}
	//userlib.DebugMsg("write to deterministic location in data store")
	userlib.DatastoreSet(storageKey, invtBytes)

	return nil
}

// Given a file struct WITH POPULATED FIELDS write this file to datastore
func writeFile(file *File, file_mac_key []byte, invt *Invitation) error {
	privFileBytes, err := json.Marshal(file.priv_file)
	if err != nil {
		return errors.New(strings.ToTitle("failed to marshal priv file"))
	}
	//userlib.DebugMsg("encrypting priv file with sym key")
	file.Enc_file = userlib.SymEnc(invt.priv_invt.File_sym_key, userlib.RandomBytes(IV_LEN), privFileBytes)
	file.MAC_hash, err = userlib.HMACEval(file_mac_key[:16], file.Enc_file)
	if err != nil {
		return errors.New(strings.ToTitle("failed to mac priv file"))
	}

	//userlib.DebugMsg("marshaling whole file")
	var fileBytes []byte

	fileBytes, err = json.Marshal(file)
	if err != nil {
		return errors.New(strings.ToTitle("failed to marshal priv file"))
	}
	//userlib.DebugMsg("writing file to data store")
	userlib.DatastoreSet(invt.priv_invt.File_ptr, fileBytes)

	return nil
}

//	 Similarly to extract invitation, extract file uses an invitation to access and populate
//			the fields of a file and returns it (along with derived mac_key)
func extractFile(userdata *User, invt *Invitation) (File, []byte, error) {
	var file File
	var file_mac_key []byte

	//userlib.DebugMsg(">>> access file")
	fileBytes, errGet := userlib.DatastoreGet(invt.priv_invt.File_ptr)
	if !errGet {
		return file, file_mac_key, errors.New(strings.ToTitle("couldn't get file"))
	}

	//userlib.DebugMsg(">>> unmarshal file")
	unmarshalErr := json.Unmarshal(fileBytes, &file)
	if unmarshalErr != nil {
		return file, file_mac_key, errors.New(strings.ToTitle("couldn't unmarshal file"))
	}

	//userlib.DebugMsg(">>> derive Mac key (from sym_key in priv_invt)")
	var mackeygenErr error
	file_mac_key, mackeygenErr = userlib.HashKDF(invt.priv_invt.File_sym_key, []byte("mac"))
	if mackeygenErr != nil {
		return file, file_mac_key, errors.New(strings.ToTitle("mac of file failed"))
	}
	//userlib.DebugMsg(">>> check mac of file")
	hmac, HMACerr := userlib.HMACEval(file_mac_key[:16], file.Enc_file)
	if HMACerr != nil {
		return file, file_mac_key, errors.New(strings.ToTitle("failed to generate mac on file enc data"))
	}
	same := userlib.HMACEqual(hmac, file.MAC_hash)
	if !same {
		return file, file_mac_key, errors.New(strings.ToTitle("mac do not match"))
	}

	//userlib.DebugMsg(">>> decrypt file")
	privFileBytes := userlib.SymDec(invt.priv_invt.File_sym_key, file.Enc_file)

	//userlib.DebugMsg(">>> unmarshal decrypted file")
	unmarshalErr = json.Unmarshal(privFileBytes, &file.priv_file)
	if unmarshalErr != nil {
		return file, file_mac_key, errors.New(strings.ToTitle("couldn't unmarshal priv file data"))
	}

	return file, file_mac_key, nil
}

// Takes raw bytes from datastore and returns an extracted invitation
//
//	used in getFileFromInvt and AcceptInvitation
//	receives the symmetric key that decrypts the invitation
func extractInvite(userdata *User, foundInvitation []byte) (Invitation, error) {
	var invt Invitation

	unmarshalErr := json.Unmarshal(foundInvitation, &invt)
	if unmarshalErr != nil {
		return invt, errors.New(strings.ToTitle("couldn't unmarshal found invitation Data"))
	}
	//userlib.DebugMsg(">>> decrypting invt access")
	privAccessBytes, accessErr := userlib.PKEDec(userdata.private_user_data.Private_Key, invt.Pub_enc_access)
	if accessErr != nil {
		return invt, errors.New(strings.ToTitle("couldn't pub decrypt invt access"))
	}
	//userlib.DebugMsg(">>> unmarshal invt access")
	unmarshalErr = json.Unmarshal(privAccessBytes, &invt.access)
	if unmarshalErr != nil {
		return invt, errors.New(strings.ToTitle("couldn't unmarshal invt access"))
	}
	//Use key of invitation creator to check validity
	pubSigKey, found := userlib.KeystoreGet(invt.access.Parent_name + "verification")
	if !found {
		return invt, errors.New(strings.ToTitle("no pubsigning  key for user with username found"))
	}

	//userlib.DebugMsg(">>> check signature")
	checkSign := userlib.DSVerify(pubSigKey, append(invt.Enc_invt, invt.Pub_enc_access...), invt.Signature)
	if checkSign != nil {
		return invt, errors.New(strings.ToTitle("signing key verification failed"))
	}

	//userlib.DebugMsg(">>> decrypting invitation")
	privInvitationBytes := userlib.SymDec(invt.access.Priv_sym_invt_key, invt.Enc_invt)

	//userlib.DebugMsg(">>> unmarshal private invitation bytes")
	unmarshalErr = json.Unmarshal(privInvitationBytes, &invt.priv_invt)
	if unmarshalErr != nil {
		return invt, errors.New(strings.ToTitle("couldn't unmarshal found priv invitation Data"))
	}

	return invt, nil
}

// Receives datastore data, extracts all chunk fields (unmarshalling, checking mac, decrypting, and unmarshalling)
func extractChunk(chunkBytes []byte, chunk *Chunk, file_sym_key []byte, file_mac_key []byte, getData bool) error {
	unmarshalErr := json.Unmarshal(chunkBytes, chunk)
	if unmarshalErr != nil {
		return errors.New(strings.ToTitle("couldn't unmarshal chunk"))
	}

	hmac, HMACerr := userlib.HMACEval(file_mac_key, chunk.Enc_priv)
	if HMACerr != nil {
		return errors.New(strings.ToTitle("failed to generate mac on file enc data"))
	}
	same := userlib.HMACEqual(hmac, chunk.MAC_hash)
	if !same {
		return errors.New(strings.ToTitle("mac do not match for chunk"))
	}

	privChunkBytes := userlib.SymDec(file_sym_key, chunk.Enc_priv)
	unmarshalErr = json.Unmarshal(privChunkBytes, &chunk.priv_chunk)
	if unmarshalErr != nil {
		return errors.New(strings.ToTitle("couldn't unmarshal priv chunk data"))
	}
	
	// Only extract data portion of chunk when want to use the data
	// (in AppendToFile we just modify Nextchunk pointer)
	if getData {
		enc_data, found := userlib.DatastoreGet(chunk.priv_chunk.Data_loc)
		if !found {
			return  errors.New(strings.ToTitle("couldn't get data"))
		}
		
		hmac, HMACerr = userlib.HMACEval(file_mac_key, enc_data)
		if HMACerr != nil {
			return errors.New(strings.ToTitle("failed to generate mac on file enc data"))
		}
		same = userlib.HMACEqual(hmac, chunk.priv_chunk.MAC_ondata)
		if !same {
			return errors.New(strings.ToTitle("data mac does not match"))
		}
		
		chunk.priv_chunk.data = userlib.SymDec(file_sym_key, enc_data)	
	} 

	return nil
}

// 
func writeIndivdualChunk(chunk *Chunk, loc uuid.UUID, invt *Invitation, file_mac_key []byte, writedata bool) error {
	if writedata {
		// Generate data loc
		chunk.priv_chunk.Data_loc = getRandomValidUUID()
		// Encrypt and mac data in priv_chunk
		enc_data := userlib.SymEnc(invt.priv_invt.File_sym_key, userlib.RandomBytes(IV_LEN), chunk.priv_chunk.data)
		
		var err error
		chunk.priv_chunk.MAC_ondata, err = userlib.HMACEval(file_mac_key[:16], enc_data)
		if err != nil {
			return errors.New(strings.ToTitle("failed to generate mac on file enc data HELLO"))
		}
		
		// Write data in priv_chunk to Data_loc
		userlib.DatastoreSet(chunk.priv_chunk.Data_loc, enc_data)
	} 
	
	privBytes, err := json.Marshal(chunk.priv_chunk)
	if err != nil {
		return errors.New(strings.ToTitle("failed to marshal a priv chunk"))
	}
	chunk.Enc_priv = userlib.SymEnc(invt.priv_invt.File_sym_key, userlib.RandomBytes(IV_LEN), privBytes)
	chunk.MAC_hash, err = userlib.HMACEval(file_mac_key[:16], chunk.Enc_priv)
	if err != nil {
		return errors.New(strings.ToTitle("failed to mac a chunk"))
	}
	chunkBytes, errMarsh := json.Marshal(chunk)
	if errMarsh != nil {
		return errors.New(strings.ToTitle("failed to marshal a chunk"))
	}
	userlib.DatastoreSet(loc, chunkBytes)
	return nil;
}

// Takes variable amount of content and writes to file chunks starting @ begin
// FIXME LEN can have overflow.
func WriteChunks(content []byte, file *File, invt *Invitation, file_mac_key []byte, begin uuid.UUID) (err error) {
	content_length := len(content)
	curr_UUID := begin
	var next_UUID uuid.UUID

	for x := 0; x < content_length; x = x + CHUNKSIZE {
		//userlib.DebugMsg("creating chunk for data from %s to %s ", x, x + CHUNKSIZE)
		var chunk Chunk
		if x+CHUNKSIZE >= content_length {
			file.priv_file.End = curr_UUID
			chunk.priv_chunk.data = content[x:content_length]
			chunk.priv_chunk.Next_chunk = uuid.Nil
		} else {
			chunk.priv_chunk.data = content[x : x+CHUNKSIZE]
			next_UUID = getRandomValidUUID()
			chunk.priv_chunk.Next_chunk = next_UUID
		}
		err := writeIndivdualChunk(&chunk, curr_UUID, invt, file_mac_key, true)
		
		if err != nil {
			return err;
		}
		
		curr_UUID = next_UUID
	}
	
	// Write back file since we changed part of it:
	err = writeFile(file, file_mac_key, invt)
	if err != nil {
		return err
	}
	
	//userlib.DebugMsg("IN APPEND File start %s, File end %s", file.priv_file.Start, file.priv_file.End)
	return nil
}

// Generates keys for encrypting user data
func generateMacHashKeys(salt []byte, password string, username string) (encKey []byte, macKey []byte, err error) {
	// generate the password keys (using the user's password and username pair)
	//userlib.DebugMsg("generate password key and enc mac key pair")
	argonInput := append(append([]byte(password), byte(48)), []byte(username)...)
	passwordMasterKey := userlib.Argon2Key(argonInput, salt, PASS_KEY_SIZE)
	//create hash key
	encKey, encKeyErr := userlib.HashKDF(passwordMasterKey, []byte("encryption"))
	if encKeyErr != nil {
		//userlib.DebugMsg("failed to generate encryption key. ")
		return nil, nil, errors.New(strings.ToTitle("failed to generate encryption key. "))
	}
	//create mac key
	macKey, macKeyErr := userlib.HashKDF(passwordMasterKey, []byte("mac"))
	if macKeyErr != nil {
		//userlib.DebugMsg("failed to generate mac key")
		return nil, nil, errors.New(strings.ToTitle("failed to generate mac key"))
	}
	// //userlib.DebugMsg(string(encKey)
	return encKey[:16], macKey[:16], nil
}