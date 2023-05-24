package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	_ "encoding/hex"
	_ "errors"
	"math/rand"
	"strconv"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const defaultPassword2 = "different"
const defaultPassword3 = "alsodifferent"
const defaultPassword4 = "stilldifferent"
const defaultPassword5 = "alsostilldifferent"

const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var denzel *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobPhone *client.User

	var charlesPhone *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	denzelFile := "denzelFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	
	Describe("Our Tests", func() {
		
		Specify("Init User: null name", func() {
			userlib.DebugMsg("Test that user with name \"\" can not be created")
			_, err := client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

		})
		Specify("Init User: username must be unique", func() {
			userlib.DebugMsg("Create user Dave (should not error)")
			_, err := client.InitUser("Dave", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Check that first creation of Dave works")
			_, err = client.InitUser("Dave", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Check that second creation of Dave fails")
		})
		Specify("Get User: Getting non existent User", func() {
			_, err = client.GetUser("Crazy Dave", "Dave")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("ensure a user not found")
		})

		Specify("Get User: bad password input", func() {
			userlib.DebugMsg("Create user Dave")
			_, err := client.InitUser("Dave", "correct_password")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Check that first creation of Dave works")
			_, err = client.GetUser("Dave", "bad_password")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Dave attempting to log in with a bad password should fail")
		})
		Specify("Init/Get User: empty password input", func() {
			userlib.DebugMsg("Create user Dave")
			_, err := client.InitUser("Dave", "")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Check that first creation of Dave works")
			_, err = client.GetUser("Dave", "")
			Expect(err).To(BeNil())
			userlib.DebugMsg("ensure works with empty password")
		})

		Specify("Init/Store User: simple store", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

		})

		Specify("Get malformed", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DatastoreClear()
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("Store/Load/append test malformed", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("file", []byte("grapes"))
			Expect(err).To(BeNil())
			userlib.DatastoreClear()
			_, err = alice.LoadFile("file")
			Expect(err).ToNot(BeNil())
			err = alice.AppendToFile("file", []byte("grapes"))
			Expect(err).ToNot(BeNil())

		})

		Specify("Init/Store User: empty file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("", []byte(contentThree))
			Expect(err).To(BeNil())

		})

		Specify("Init/Store User: simple multiple", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile1", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile2", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile3", []byte(contentOne))
			Expect(err).To(BeNil())

		})

		Specify("Init/Store User: simple multiple of same file same owner", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

		})
		Specify("Init/Get/Store User: simple multiple", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile1", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile2", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile3", []byte(contentOne))
			Expect(err).To(BeNil())

		})

		Specify("Init/Get/Store User: simple multiple of same file same owner", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

		})

		Specify("Init/Store/Load User: simple", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			_, err = alice.LoadFile("aliceFile")
			Expect(err).To(BeNil())

		})
		Specify("Init/Store/Load User: bad filename", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			_, err = alice.LoadFile("BadFile")
			Expect(err).ToNot(BeNil())

		})
		Specify("Init/Store/Load User: check contents short", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("aliceFile", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			fileContent, err1 := alice.LoadFile("aliceFile")
			Expect(err1).To(BeNil())
			userlib.DebugMsg("expected %v actual %v", contentOne, fileContent)
			Expect(fileContent).To(Equal([]byte(contentOne)))

		})
		Specify("Init/Store/Load User: check contents long", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			data := genBytes(100000)

			userlib.DebugMsg("Storing file data: %s", data)
			err = alice.StoreFile("aliceFile", data)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			fileContent, err1 := alice.LoadFile("aliceFile")
			Expect(err1).To(BeNil())
			Expect(fileContent).To(Equal([]byte(data)))
		})
		Specify("Init/Store/Load User: store load store load  short, long ", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			data := genBytes(100)

			userlib.DebugMsg("Storing file data: %s", data)
			err = alice.StoreFile("aliceFile", data)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			fileContent, err1 := alice.LoadFile("aliceFile")
			Expect(err1).To(BeNil())
			Expect(fileContent).To(Equal([]byte(data)))

			// Store again to the same loc
			userlib.DebugMsg("Restore new file at same location")
			newData := genBytes(1000)

			userlib.DebugMsg("Storing file data: %s", newData)
			err = alice.StoreFile("aliceFile", newData)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			newFileContent, err2 := alice.LoadFile("aliceFile")
			Expect(err2).To(BeNil())
			Expect(newFileContent).To(Equal([]byte(newData)))
		})

		Specify("Init/Store/Load User: store load store load  long, short ", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			data := genBytes(1000)

			userlib.DebugMsg("Storing file data: %s", data)
			err = alice.StoreFile("aliceFile", data)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			fileContent, err1 := alice.LoadFile("aliceFile")
			Expect(err1).To(BeNil())
			Expect(fileContent).To(Equal([]byte(data)))

			// Store again to the same loc
			userlib.DebugMsg("Restore new file at same location")
			newData := genBytes(100)

			userlib.DebugMsg("Storing file data: %s", newData)
			err = alice.StoreFile("aliceFile", newData)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			newFileContent, err2 := alice.LoadFile("aliceFile")
			Expect(err2).To(BeNil())
			Expect(newFileContent).To(Equal([]byte(newData)))
		})

		Specify(" store load bulk test multiple sessions", func() {
			userlib.DebugMsg("Initializing user Alice.")
			a1, err1 := client.InitUser("alice", defaultPassword)
			Expect(err1).To(BeNil())
			a2, err2 := client.GetUser("alice", defaultPassword)
			Expect(err2).To(BeNil())
			a3, err3 := client.GetUser("alice", defaultPassword)
			var err error
			Expect(err3).To(BeNil())
			for i := 0; i < 50; i = i + 1 {
				currData := genBytes(6969)
				var file []byte
				if i%3 == 1 {
					err = a1.StoreFile("a1"+string(currData[:16]), currData)
					Expect(err).To(BeNil())
					file, err = a1.LoadFile("a1" + string(currData[:16]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))
				}
				if i%3 == 2 {
					err = a2.StoreFile("a2"+string(currData[:16]), currData)
					Expect(err).To(BeNil())
					file, err = a2.LoadFile("a2" + string(currData[:16]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))
				}
				if i%3 == 0 {
					err = a3.StoreFile("a3"+string(currData[:16]), currData)
					Expect(err).To(BeNil())
					file, err = a3.LoadFile("a3" + string(currData[:16]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))
				}

			}

		})

		Specify(" store load bulk test multiple sessions high collision", func() {
			userlib.DebugMsg("Initializing user Alice.")
			a1, err1 := client.InitUser("alice", defaultPassword)
			Expect(err1).To(BeNil())
			a2, err2 := client.GetUser("alice", defaultPassword)
			Expect(err2).To(BeNil())
			a3, err3 := client.GetUser("alice", defaultPassword)
			var err error
			Expect(err3).To(BeNil())
			for i := 0; i < 100; i = i + 1 {
				rand.Seed(1234)
				currData := genBytes(uint32(rand.Intn(8000)))
				var file []byte
				if i%3 == 1 {
					err = a1.StoreFile(string(currData[:1]), currData)
					Expect(err).To(BeNil())
					file, err = a1.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))
				}
				if i%3 == 2 {
					err = a2.StoreFile(string(currData[:1]), currData)
					Expect(err).To(BeNil())
					file, err = a2.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))
				}
				if i%3 == 0 {
					err = a3.StoreFile(string(currData[:1]), currData)
					Expect(err).To(BeNil())
					file, err = a3.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))
				}

			}

		})
		Specify("Multiple Sessions Single File: Store Load Interweave", func() {

			var a1 *client.User
			var a2 *client.User
			var a3 *client.User
			var file []byte
			var err error

			userlib.DebugMsg("Initializing user Alice.")
			userlib.DebugMsg("Get 3 separate sessions for Alice.")
			a1, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			a2, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			a3, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			data1 := genBytes(100)
			data2 := genBytes(100)
			data3 := genBytes(100)

			// All sessions store their own data
			err = a1.StoreFile("alice_file", data1)
			Expect(err).To(BeNil())
			err = a2.StoreFile("alice_file", data2)
			Expect(err).To(BeNil())
			err = a3.StoreFile("alice_file", data3)
			Expect(err).To(BeNil())

			// All sessions should see most recent
			file, err = a1.LoadFile("alice_file")
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(file)))
			file, err = a2.LoadFile("alice_file")
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(file)))
			file, err = a3.LoadFile("alice_file")
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(file)))

			// Session 1 stores data
			err = a1.StoreFile("alice_file", data1)
			Expect(err).To(BeNil())

			// All sessions should see most recent data
			file, err = a1.LoadFile("alice_file")
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(file)))
			file, err = a2.LoadFile("alice_file")
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(file)))
			file, err = a3.LoadFile("alice_file")
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(file)))

		})

		Specify(" store load append bulk test multiple sessions high collision", func() {
			userlib.DebugMsg("Initializing user Alice.")
			a1, err1 := client.InitUser("alice", defaultPassword)
			Expect(err1).To(BeNil())
			a2, err2 := client.GetUser("alice", defaultPassword)
			Expect(err2).To(BeNil())
			a3, err3 := client.GetUser("alice", defaultPassword)
			var err error
			Expect(err3).To(BeNil())
			for i := 0; i < 100; i = i + 1 {
				rand.Seed(1234)
				currData := genBytes(uint32(rand.Intn(8000)))
				addlData := genBytes(uint32(rand.Intn(8000)))
				var file []byte
				if i%3 == 1 {
					err = a1.StoreFile(string(currData[:1]), currData)
					Expect(err).To(BeNil())
					file, err = a1.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))

					err = a1.AppendToFile(string(currData[:1]), addlData)
					Expect(err).To(BeNil())
					file, err = a1.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(append(currData, addlData...)).To(Equal([]byte(file)))

				}
				if i%3 == 2 {
					err = a2.StoreFile(string(currData[:1]), currData)
					Expect(err).To(BeNil())
					file, err = a2.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))

					err = a2.AppendToFile(string(currData[:1]), addlData)
					Expect(err).To(BeNil())
					file, err = a2.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(append(currData, addlData...)).To(Equal([]byte(file)))
				}
				if i%3 == 0 {
					err = a3.StoreFile(string(currData[:1]), currData)
					Expect(err).To(BeNil())
					file, err = a3.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(currData).To(Equal([]byte(file)))

					err = a3.AppendToFile(string(currData[:1]), addlData)
					Expect(err).To(BeNil())
					file, err = a3.LoadFile(string(currData[:1]))
					Expect(err).To(BeNil())
					Expect(append(currData, addlData...)).To(Equal([]byte(file)))
				}
			}

		})

		Specify(" multiple sessions random append store load high collision", func() {
			userlib.DebugMsg("Initializing user Alice.")
			a1, err1 := client.InitUser("alice", defaultPassword)
			Expect(err1).To(BeNil())
			a2, err2 := client.GetUser("alice", defaultPassword)
			Expect(err2).To(BeNil())
			a3, err3 := client.GetUser("alice", defaultPassword)
			var err error
			stat := 0
			loops := 400
			// factor := 0.01 // probablistic 2/3 * 1/64
			Expect(err3).To(BeNil())
			for i := 0; i < loops; i = i + 1 {
				rand.Seed(1234)
				currData := genBytes(uint32(rand.Intn(8000)))
				addlData := genBytes(uint32(rand.Intn(100)))
				var file []byte
				var postFile []byte
				j := rand.Intn(3)
				if i%3 == 1 {
					if j%3 == 0 {
						err = a1.StoreFile(string(currData[:1]), currData)
						Expect(err).To(BeNil())
					}
					if j%3 == 1 {
						file, err = a1.LoadFile(string(currData[:1]))
						if err != nil {
							err = a1.StoreFile(string(currData[:1]), currData)
							Expect(err).To(BeNil())
							userlib.DebugMsg("TRIED TO LOAD BEFORE STORE STORING THEN LOADING")
							stat = stat + 1
							file, err = a1.LoadFile(string(currData[:1]))
						}
						Expect(err).To(BeNil())
						Expect(currData).To(Equal([]byte(file)))
					}
					if j%3 == 2 {
						err = a1.AppendToFile(string(currData[:1]), addlData)
						if err != nil {
							err = a1.StoreFile(string(currData[:1]), currData)
							Expect(err).To(BeNil())
							userlib.DebugMsg("TRIED TO LOAD BEFORE STORE STORING THEN LOADING")
							stat = stat + 1
							file, err = a1.LoadFile(string(currData[:1]))
							Expect(err).To(BeNil())
							err = a1.AppendToFile(string(currData[:1]), addlData)
							postFile, err = a1.LoadFile(string(currData[:1]))
						}
						Expect(err).To(BeNil())
						Expect(append(file, addlData...)).To(Equal([]byte(postFile)))
					}
				}

				if i%3 == 2 {
					if j%3 == 0 {
						err = a2.StoreFile(string(currData[:1]), currData)
						Expect(err).To(BeNil())
					}
					if j%3 == 1 {
						file, err = a2.LoadFile(string(currData[:1]))
						if err != nil {
							err = a2.StoreFile(string(currData[:1]), currData)
							Expect(err).To(BeNil())
							userlib.DebugMsg("TRIED TO LOAD BEFORE STORE STORING THEN LOADING")
							stat = stat + 1
							file, err = a2.LoadFile(string(currData[:1]))
						}
						Expect(err).To(BeNil())
						Expect(currData).To(Equal([]byte(file)))
					}
					if j%3 == 2 {
						err = a2.AppendToFile(string(currData[:1]), addlData)
						if err != nil {
							err = a2.StoreFile(string(currData[:1]), currData)
							Expect(err).To(BeNil())
							userlib.DebugMsg("TRIED TO LOAD BEFORE STORE STORING THEN LOADING")
							stat = stat + 1
							file, err = a2.LoadFile(string(currData[:1]))
							Expect(err).To(BeNil())
							err = a2.AppendToFile(string(currData[:1]), addlData)
							postFile, err = a2.LoadFile(string(currData[:1]))
						}
						Expect(err).To(BeNil())
						Expect(append(file, addlData...)).To(Equal([]byte(postFile)))
					}
				}
				if i%3 == 0 {
					if j%3 == 0 {
						err = a3.StoreFile(string(currData[:1]), currData)
						Expect(err).To(BeNil())
					}
					if j%3 == 1 {
						file, err = a3.LoadFile(string(currData[:1]))
						if err != nil {
							err = a3.StoreFile(string(currData[:1]), currData)
							Expect(err).To(BeNil())
							userlib.DebugMsg("TRIED TO LOAD BEFORE STORE STORING THEN LOADING")
							stat = stat + 1
							file, err = a3.LoadFile(string(currData[:1]))
						}
						Expect(err).To(BeNil())
						Expect(currData).To(Equal([]byte(file)))
					}
					if j%3 == 2 {
						err = a3.AppendToFile(string(currData[:1]), addlData)
						if err != nil {
							err = a3.StoreFile(string(currData[:1]), currData)
							Expect(err).To(BeNil())
							userlib.DebugMsg("TRIED TO LOAD BEFORE STORE STORING THEN LOADING")
							stat = stat + 1
							file, err = a3.LoadFile(string(currData[:1]))
							Expect(err).To(BeNil())
							err = a3.AppendToFile(string(currData[:1]), addlData)
							postFile, err = a3.LoadFile(string(currData[:1]))
						}
						Expect(err).To(BeNil())
						Expect(append(file, addlData...)).To(Equal([]byte(postFile)))
					}
				}
			}

		})

	})

	Specify("Sharing Test: Share/Write/Load/Append for bushy tree users.", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		A1, _ := client.InitUser("A1", defaultPassword)
		A2, _ := client.InitUser("A2", defaultPassword)
		A3, _ := client.InitUser("A3", defaultPassword)

		B11, _ := client.InitUser("B11", defaultPassword)
		B12, _ := client.InitUser("B12", defaultPassword)
		B13, _ := client.InitUser("B13", defaultPassword)

		B21, _ := client.InitUser("B21", defaultPassword)
		B22, _ := client.InitUser("B22", defaultPassword)
		B23, _ := client.InitUser("B23", defaultPassword)

		B31, _ := client.InitUser("B31", defaultPassword)
		B32, _ := client.InitUser("B32", defaultPassword)
		B33, _ := client.InitUser("B33", defaultPassword)

		var userList []*client.User
		userList = append(userList, A1, A2, A3, B11, B12, B13, B21, B22, B23, B31, B32, B33)
		var nameList []string
		nameList = append(nameList, "A1", "A2", "A3", "B11", "B12", "B13", "B21", "B22", "B23", "B31", "B32", "B33")

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invite, err := alice.CreateInvitation(aliceFile, "A1")
		Expect(err).To(BeNil())
		err = A1.AcceptInvitation("alice", invite, "A1")
		Expect(err).To(BeNil())
		invite, err = alice.CreateInvitation(aliceFile, "A2")
		Expect(err).To(BeNil())
		err = A2.AcceptInvitation("alice", invite, "A2")
		Expect(err).To(BeNil())
		invite, err = alice.CreateInvitation(aliceFile, "A3")
		Expect(err).To(BeNil())
		err = A3.AcceptInvitation("alice", invite, "A3")
		Expect(err).To(BeNil())

		invite, err = A1.CreateInvitation("A1", "B11")
		Expect(err).To(BeNil())
		err = B11.AcceptInvitation("A1", invite, "B11")
		Expect(err).To(BeNil())

		invite, err = A1.CreateInvitation("A1", "B12")
		Expect(err).To(BeNil())
		err = B12.AcceptInvitation("A1", invite, "B12")
		Expect(err).To(BeNil())

		invite, err = A1.CreateInvitation("A1", "B13")
		Expect(err).To(BeNil())
		err = B13.AcceptInvitation("A1", invite, "B13")
		Expect(err).To(BeNil())

		invite, err = A2.CreateInvitation("A2", "B21")
		Expect(err).To(BeNil())
		err = B21.AcceptInvitation("A2", invite, "B21")
		Expect(err).To(BeNil())

		invite, err = A2.CreateInvitation("A2", "B22")
		Expect(err).To(BeNil())
		err = B22.AcceptInvitation("A2", invite, "B22")
		Expect(err).To(BeNil())

		invite, err = A2.CreateInvitation("A2", "B23")
		Expect(err).To(BeNil())
		err = B23.AcceptInvitation("A2", invite, "B23")
		Expect(err).To(BeNil())

		invite, err = A3.CreateInvitation("A3", "B31")
		Expect(err).To(BeNil())
		err = B31.AcceptInvitation("A3", invite, "B31")
		Expect(err).To(BeNil())

		invite, err = A3.CreateInvitation("A3", "B32")
		Expect(err).To(BeNil())
		err = B32.AcceptInvitation("A3", invite, "B32")
		Expect(err).To(BeNil())

		invite, err = A3.CreateInvitation("A3", "B33")
		Expect(err).To(BeNil())
		err = B33.AcceptInvitation("A3", invite, "B33")
		Expect(err).To(BeNil())

		loops := 200
		rand.Seed(5678)
		for i := 0; i < loops; i = i + 1 {
			currData := genBytes(uint32(rand.Intn(8000)))
			addl := genBytes(uint32(rand.Intn(100)))
			reader := rand.Intn(len(nameList))
			modifier := rand.Intn(len(nameList))
			op := rand.Intn(2)
			//get reader
			RUSER := userList[reader]
			RUSERname := nameList[reader]

			WUSER := userList[modifier]
			WUSERname := nameList[modifier]
			if op%2 == 0 {
				WUSER.StoreFile(WUSERname, currData)
				file, _ := RUSER.LoadFile(RUSERname)
				Expect(currData).To(Equal([]byte(file)))
			} else {
				beforeFile, _ := RUSER.LoadFile(RUSERname)
				WUSER.AppendToFile(WUSERname, addl)
				file, _ := RUSER.LoadFile(RUSERname)
				Expect(append(beforeFile, addl...)).To(Equal([]byte(file)))

			}

		}

	})

	Specify("Sharing Test: 3 chained users. Sub user STORES and parents see", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Checking that Alice can still load the file.")
		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		userlib.DebugMsg("Checking that Bob can load the file.")
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())

		userlib.DebugMsg("Charlie accepts the invitation")
		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Checking that Charlie can load the file.")
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		userlib.DebugMsg("Charlie stores into shared file")
		charles.StoreFile(charlesFile, []byte(contentThree))

		userlib.DebugMsg("Checking that Alice sees Charlie's changes.")
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))

		userlib.DebugMsg("Checking that Bob sees Charlie's changes.")
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
	})

	Specify("Sharing Test: 4 chained users. Sub user STORES and all parents see", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		denzel, err = client.InitUser("denzel", defaultPassword4)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())

		userlib.DebugMsg("Charlie accepts the invitation")
		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Charlie creating invite for Denzel for file %s, and Charlie accepting invite under name %s.", charlesFile, denzelFile)
		invite, err = charles.CreateInvitation(charlesFile, "denzel")
		Expect(err).To(BeNil())

		userlib.DebugMsg("Denzel accepts the invitation")
		err = denzel.AcceptInvitation("charles", invite, denzelFile)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Check that all can still load the file")
		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		userlib.DebugMsg("Denzel stores into shared file")
		denzel.StoreFile(denzelFile, []byte(contentThree))

		userlib.DebugMsg("Checking that all parents see changes")
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
	})

	Specify("Sharing Test: 5 chained users. Sub user STORES and all parents see", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		denzel, err = client.InitUser("denzel", defaultPassword4)
		Expect(err).To(BeNil())

		eve, err = client.InitUser("eve", defaultPassword5)
		Expect(err).To(BeNil())

		alice.StoreFile(aliceFile, []byte(contentOne))
		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())
		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())

		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())
		invite, err = charles.CreateInvitation(charlesFile, "denzel")
		Expect(err).To(BeNil())

		err = denzel.AcceptInvitation("charles", invite, denzelFile)
		Expect(err).To(BeNil())
		invite, err = denzel.CreateInvitation(denzelFile, "eve")
		Expect(err).To(BeNil())

		err = eve.AcceptInvitation("denzel", invite, eveFile)
		Expect(err).To(BeNil())

		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = eve.LoadFile(eveFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		userlib.DebugMsg("Eve stores into shared file")
		eve.StoreFile(eveFile, []byte(contentThree))

		userlib.DebugMsg("Checking that all parents see changes")
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentThree)))
	})

	Specify("Sharing Test: 5 chained users. Sub user APPENDS and all parents see", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		denzel, err = client.InitUser("denzel", defaultPassword4)
		Expect(err).To(BeNil())

		eve, err = client.InitUser("eve", defaultPassword5)
		Expect(err).To(BeNil())

		alice.StoreFile(aliceFile, []byte(contentOne))
		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())
		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())

		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())
		invite, err = charles.CreateInvitation(charlesFile, "denzel")
		Expect(err).To(BeNil())

		err = denzel.AcceptInvitation("charles", invite, denzelFile)
		Expect(err).To(BeNil())
		invite, err = denzel.CreateInvitation(denzelFile, "eve")
		Expect(err).To(BeNil())

		err = eve.AcceptInvitation("denzel", invite, eveFile)
		Expect(err).To(BeNil())

		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))
		data, err = eve.LoadFile(eveFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		userlib.DebugMsg("Eve Appends shared file")
		eve.AppendToFile(eveFile, []byte(contentThree))
		userlib.DebugMsg("((Check that empty string append works))")
		eve.AppendToFile(eveFile, []byte(""))	// quick check that empty string append works

		userlib.DebugMsg("Checking that all parents see changes")
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentThree)...)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentThree)...)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentThree)...)))
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentThree)...)))
	})

	Specify("Revoke Test: 2 branches revoke 1 check access", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())
		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())
		denzel, err = client.InitUser("denzel", defaultPassword4)
		Expect(err).To(BeNil())
		eve, err = client.InitUser("eve", defaultPassword5)
		Expect(err).To(BeNil())

		alice.StoreFile(aliceFile, []byte(contentOne))

		// Branch 1
		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())
		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())

		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())
		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())

		// Branch 2
		invite, err = alice.CreateInvitation(aliceFile, "denzel")
		Expect(err).To(BeNil())
		err = denzel.AcceptInvitation("alice", invite, denzelFile)
		Expect(err).To(BeNil())

		invite, err = denzel.CreateInvitation(denzelFile, "eve")
		Expect(err).To(BeNil())
		err = eve.AcceptInvitation("denzel", invite, eveFile)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Eve Appends shared file")
		eve.AppendToFile(eveFile, []byte(contentTwo))

		userlib.DebugMsg("Checking that all users see changes")
		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentTwo)...)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentTwo)...)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentTwo)...)))
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append([]byte(contentOne), []byte(contentTwo)...)))

		userlib.DebugMsg("Bob Stores to shared file")
		bob.StoreFile(bobFile, []byte(contentTwo))

		userlib.DebugMsg("Checking that all users see changes")
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentTwo)))
		data, err = bob.LoadFile(bobFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentTwo)))
		data, err = charles.LoadFile(charlesFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentTwo)))
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentTwo)))

		// REVOKE BRANCH 1
		userlib.DebugMsg("REVOKE BRANCH 1")
		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		// Check access rights
		userlib.DebugMsg("Check Bob and Charlie can't access file")
		err = bob.AppendToFile(bobFile, []byte(contentTwo))
		Expect(err).ToNot(BeNil())
		err = charles.AppendToFile(charlesFile, []byte(contentTwo))
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Check Denzel and Eve can access file")
		err = denzel.AppendToFile(denzelFile, []byte(contentTwo))
		Expect(err).To(BeNil())
		err = eve.AppendToFile(eveFile, []byte(contentTwo))
		Expect(err).To(BeNil())

		// All still shared users can see changes
		userlib.DebugMsg("Alice Loads file")
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append(append([]byte(contentTwo), []byte(contentTwo)...), []byte(contentTwo)...)))
		userlib.DebugMsg("Other shared users load file")
		data, err = denzel.LoadFile(denzelFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append(append([]byte(contentTwo), []byte(contentTwo)...), []byte(contentTwo)...)))
		data, err = eve.LoadFile(eveFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append(append([]byte(contentTwo), []byte(contentTwo)...), []byte(contentTwo)...)))

		// Non-shared can't load file
		_, err = bob.LoadFile(bobFile)
		Expect(err).ToNot(BeNil())
		_, err = charles.LoadFile(charlesFile)
		Expect(err).ToNot(BeNil())
	})
	Specify("Simple revoke ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())
		alice.StoreFile(aliceFile, []byte(contentOne))

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())
		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())

		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())
		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		userlib.DebugMsg("STORE")
		err = alice.StoreFile(aliceFile, []byte("FART LOOP"))
		Expect(err).To(BeNil())
		userlib.DebugMsg("Append")
		err = alice.AppendToFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())
		A, err := alice.LoadFile(aliceFile)
		userlib.DebugMsg("this is file cont %v", A)
		Expect(err).To(BeNil())

		_, err = bob.LoadFile(bobFile)
		Expect(err).ToNot(BeNil())

		_, err = charles.LoadFile(charlesFile)
		Expect(err).ToNot(BeNil())
	})

	Specify("add mult revoke mult", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		alice.StoreFile(aliceFile, []byte(contentOne))

		A1, _ := client.InitUser("A1", defaultPassword)
		A2, _ := client.InitUser("A2", defaultPassword)
		A3, _ := client.InitUser("A3", defaultPassword)

		invite, err := alice.CreateInvitation(aliceFile, "A1")
		Expect(err).To(BeNil())
		err = A1.AcceptInvitation("alice", invite, "A1")
		Expect(err).To(BeNil())
		invite, err = alice.CreateInvitation(aliceFile, "A2")
		Expect(err).To(BeNil())
		err = A2.AcceptInvitation("alice", invite, "A2")
		Expect(err).To(BeNil())
		invite, err = alice.CreateInvitation(aliceFile, "A3")
		Expect(err).To(BeNil())
		err = A3.AcceptInvitation("alice", invite, "A3")
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, "A1")
		Expect(err).To(BeNil())
		userlib.DebugMsg("A1 worked")
		err = alice.RevokeAccess(aliceFile, "A2")
		Expect(err).To(BeNil())
		userlib.DebugMsg("A2 worked")
		err = alice.RevokeAccess(aliceFile, "A3")
		Expect(err).To(BeNil())
		userlib.DebugMsg("A3 worked")

	})
	Specify("Simple revoke - large file (>1 chunk)", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())
		alice.StoreFile(aliceFile, []byte(contentOne))
		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		large_file_content := genBytes(5000)
		userlib.DebugMsg("STORE")
		err = alice.StoreFile(aliceFile, large_file_content)
		Expect(err).To(BeNil())

		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())
		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())

		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())
		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		userlib.DebugMsg("REVOKED USERS TRY LOAD")
		_, err = bob.LoadFile(bobFile)
		Expect(err).ToNot(BeNil())

		_, err = charles.LoadFile(charlesFile)
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Append")
		err = alice.AppendToFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append(large_file_content, []byte(contentOne)...)))
	})

	Specify("Simple revoke - multiple sessions", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())
		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())
		denzel, err = client.InitUser("denzel", defaultPassword3)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Initializing another session of Alice, Bob, and Charlie.")
		alicePhone, err = client.GetUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bobPhone, err = client.GetUser("bob", defaultPassword2)
		Expect(err).To(BeNil())
		charlesPhone, err = client.GetUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		large_file_content := genBytes(2000)
		more_large_file_content := genBytes(500)
		expected_contents := append(large_file_content, more_large_file_content...)

		userlib.DebugMsg("alice STORE")
		err = alice.StoreFile(aliceFile, large_file_content)
		Expect(err).To(BeNil())

		userlib.DebugMsg("alicePhone APPEND")
		err = alice.AppendToFile(aliceFile, more_large_file_content)
		Expect(err).To(BeNil())

		userlib.DebugMsg("alice LOAD")
		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(expected_contents))

		userlib.DebugMsg("alice SHARE")
		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())
		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).To(BeNil())

		invite, err = bob.CreateInvitation(bobFile, "charles")
		Expect(err).To(BeNil())
		err = charles.AcceptInvitation("bob", invite, charlesFile)
		Expect(err).To(BeNil())

		invite, err = bob.CreateInvitation(bobFile, "denzel")
		Expect(err).To(BeNil())

		err = denzel.AcceptInvitation("bob", invite, denzelFile)
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		userlib.DebugMsg("REVOKED USERS TRY LOAD")
		_, err = bob.LoadFile(bobFile)
		Expect(err).ToNot(BeNil())
		_, err = bobPhone.LoadFile(bobFile)
		Expect(err).ToNot(BeNil())

		// Re-Get charles after share and revoke
		charles, err = client.GetUser("charles", defaultPassword3)
		Expect(err).To(BeNil())
		_, err = charles.LoadFile(charlesFile)
		Expect(err).ToNot(BeNil())
		_, err = charlesPhone.LoadFile(charlesFile)
		Expect(err).ToNot(BeNil())

		_, err = denzel.LoadFile(denzelFile)
		Expect(err).ToNot(BeNil())

		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(expected_contents))

		err = alice.AppendToFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal(append(expected_contents, contentOne...)))
	})

	Specify("Load before store", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		_, err = alice.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())

	})

	Specify("Append before store", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.AppendToFile(aliceFile, []byte("greenbay"))
		Expect(err).ToNot(BeNil())
	})
	Specify("Revoke before store", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).ToNot(BeNil())

	})
	Specify("Revoke nonexistant user", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.StoreFile(aliceFile, []byte("warts"))
		Expect(err).To(BeNil())
		err = alice.RevokeAccess(aliceFile, "WART")
		Expect(err).ToNot(BeNil())

	})
	Specify("Revoke unshared user", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.StoreFile(aliceFile, []byte("warts"))
		Expect(err).To(BeNil())
		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).ToNot(BeNil())

	})

	Specify("EffAppend : append takes same time regardless of file size", func() {
		userlib.DebugMsg("Initializing user Alice.")
		alice, err = client.InitUser("alice", defaultPassword)

		// From Spec
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}

		small_file_content := genBytes(20)
		alice.StoreFile(aliceFile, small_file_content)
		Expect(err).To(BeNil())

		bw1 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})

		large_file_content := genBytes(1000) // several chunks
		alice.StoreFile(aliceFile, large_file_content)
		Expect(err).To(BeNil())

		bw2 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})

		// Bandwidths should be very similar
		userlib.DebugMsg("before %v after %v", bw1, bw2)
		low := pDiffBounded(float64(bw1), float64(bw2), 5)
		Expect(low).To(Equal(true))
	})

	Specify("EffAppend : append changes based on append size", func() {
		userlib.DebugMsg("Initializing user Alice.")
		alice, err = client.InitUser("alice", defaultPassword)

		// From Spec
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}

		small_file_content := genBytes(20)
		large_file_content := genBytes(1000) // several chunks
		alice.StoreFile(aliceFile, small_file_content)
		Expect(err).To(BeNil())

		bw1 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, small_file_content) // Append same small amount
		})

		
		alice.StoreFile(aliceFile, small_file_content)
		Expect(err).To(BeNil())

		bw2 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, large_file_content) // Append same small amount
		})

		// Bandwidths should be very similar
		userlib.DebugMsg("before %v after %v", bw1, bw2)
		Expect(bw1 < bw2).To(Equal(true))
	})

	Specify("EffAppend - Large Number of Files", func() {
		userlib.DebugMsg("Initializing user Alice.")
		alice, err = client.InitUser("alice", defaultPassword)

		// From Spec
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}

		file_content := genBytes(1000)
		alice.StoreFile(aliceFile, file_content)
		Expect(err).To(BeNil())

		bw1 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})

		// Create a large number of files in Alice's userspace
		for i := 1; i < 100; i++ {
			alice.StoreFile("file num"+strconv.Itoa(i), []byte(contentThree))
			Expect(err).To(BeNil())
		}

		alice.StoreFile(aliceFile, file_content)
		Expect(err).To(BeNil())

		bw2 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})

		// Bandwidths should be very similar even if Alice owns many files
		low := pDiffBounded(float64(bw1), float64(bw2), 2)
		Expect(low).To(Equal(true))
	})
	// From Spec: Append must scalar linearly wih only the 
	// size of data being appending and the number of users the file is shared with
	Specify("EffAppend - check linear in share", func() {
		userlib.DebugMsg("Initializing user Alice.")
		alice, err = client.InitUser("alice", defaultPassword)
		bob, err = client.InitUser("bob", defaultPassword2)

		// From Spec
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}

		file_content := genBytes(1000)
		alice.StoreFile(aliceFile, file_content)
		Expect(err).To(BeNil())	
		
		// Share with 1 User
		invt, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())
		err = bob.AcceptInvitation("alice", invt, "bob")
		Expect(err).To(BeNil())

		bw0 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})

		// Shared w 5 Users
		for i := 0; i < 4; i++ {
			tempUser, err := client.InitUser(strconv.Itoa(i), defaultPassword)
			Expect(err).To(BeNil())
			tempInvt, err := alice.CreateInvitation(aliceFile, strconv.Itoa(i))
			Expect(err).To(BeNil())
			err = tempUser.AcceptInvitation("alice", tempInvt, strconv.Itoa(i))
			Expect(err).To(BeNil())
		}

		alice.StoreFile(aliceFile, file_content)
		Expect(err).To(BeNil())

		bw1 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})

		// Shared w 25 Users
		for i := 5; i < 24; i++ {
			tempUser, err := client.InitUser(strconv.Itoa(i), defaultPassword)
			Expect(err).To(BeNil())
			tempInvt, err := alice.CreateInvitation(aliceFile, strconv.Itoa(i))
			Expect(err).To(BeNil())
			err = tempUser.AcceptInvitation("alice", tempInvt, strconv.Itoa(i))
			Expect(err).To(BeNil())
		}
		
		alice.StoreFile(aliceFile, file_content)
		Expect(err).To(BeNil())

		bw2 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})

		// Shared w 100 Users
		for i := 24; i < 99; i++ {
			tempUser, err := client.InitUser(strconv.Itoa(i), defaultPassword)
			Expect(err).To(BeNil())
			tempInvt, err := alice.CreateInvitation(aliceFile, strconv.Itoa(i))
			Expect(err).To(BeNil())
			err = tempUser.AcceptInvitation("alice", tempInvt, strconv.Itoa(i))
			Expect(err).To(BeNil())
		}
		
		alice.StoreFile(aliceFile, file_content)
		Expect(err).To(BeNil())

		bw3 := measureBandwidth(func() {
			alice.AppendToFile(aliceFile, []byte(contentOne)) // Append same small amount
		})
		
		// Check that Append bandwidth scales linearly with number of shared users
		userlib.DebugMsg("bw0 %v, bw1 %v, bw2 %v, bw3 %v",bw0,  bw1, bw2, bw3)
		slopeFirst := float64((bw1 - bw0)/(5 - 1))
		
		slopeSecond := float64((bw2 -bw1)/(25 - 5))
		
		slopeThird := float64((bw3 - bw2)/(100 - 25))

		slopeTotal := float64((bw3 - bw0)/(100 - 1))
		userlib.DebugMsg("slopeFirst, %v slopeSecond %v, slopeThird %v",slopeFirst, slopeSecond, slopeThird)
		

		low := pDiffBounded(slopeFirst, slopeSecond, 10)
		Expect(low).To(Equal(true))
		low = pDiffBounded(slopeThird, slopeSecond, 10)
		Expect(low).To(Equal(true))
		low= pDiffBounded(slopeThird, slopeFirst, 10)
		Expect(low).To(Equal(true))
		low= pDiffBounded(slopeTotal, slopeFirst, 10)
		Expect(low).To(Equal(true))

		
	})

	Specify("Malitcious GET ", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		userlib.DatastoreSet(keys[0], []byte("garbage"))
		_, err = client.GetUser("alice", defaultPassword)
		Expect(err).ToNot(BeNil())
	})
	Specify("Malitcious Load  file struct ", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		before := userlib.DatastoreGetMap()
		beforeKeys := make([]uuid.UUID, 0, len(before))
		for u := range before {
			beforeKeys = append(beforeKeys, u)
		}

		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).To(BeNil())
		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		for _, v1 := range keys {
			contained := false

			for _, v2 := range beforeKeys {
				userlib.DebugMsg("before %v, after %v ", v1, v2)
				userlib.DebugMsg("ENTERED ONCE")
				if v1 == v2 {
					contained = true
				}
			}
			if !contained {
				userlib.DebugMsg("ENTERED ONCE")
				userlib.DatastoreSet(v1, []byte("garbage"))
			}
		}
		_, err = alice.LoadFile("grapes")
		Expect(err).ToNot(BeNil())
	})
	Specify("Malitcious Load  chunk struct ", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).To(BeNil())
		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		for i, _ := range keys {
			userlib.DatastoreSet(keys[i], []byte("garbage"))
		}
		//userlib.DatastoreSet(keys[0], []byte("garbage"))

		_, err = alice.LoadFile("grapes")
		Expect(err).ToNot(BeNil())
	})
	Specify("Malitcious Append  chunk struct ", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).To(BeNil())
		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		userlib.DatastoreSet(keys[0], []byte("garbage"))
		userlib.DatastoreSet(keys[1], []byte("garbage"))
		userlib.DatastoreSet(keys[2], []byte("garbage"))
		_, err = alice.LoadFile("grapes")
		Expect(err).ToNot(BeNil())
	})
	Specify("Malitcious Append  file struct ", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).To(BeNil())
		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		userlib.DatastoreSet(keys[0], []byte("garbage"))
		userlib.DatastoreSet(keys[1], []byte("garbage"))
		_, err = alice.LoadFile("grapes")
		Expect(err).ToNot(BeNil())
	})

	Specify("using wrong invite", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = charles.AcceptInvitation("alice", invite, charlesFile)
		Expect(err).ToNot(BeNil())
	})

	Specify("Invitation to nonexistant user ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		_, err := alice.CreateInvitation(aliceFile, "crab")
		Expect(err).ToNot(BeNil())
	})

	Specify("accept malformed invitation ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invt, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		for i, _ := range keys {
			userlib.DatastoreSet(keys[i], []byte("garbage"))
		}
		err = bob.AcceptInvitation("alice", invt, charlesFile)
		Expect(err).ToNot(BeNil())

	})

	Specify("non existant user create invite ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
		var bad *client.User
		_, err := bad.CreateInvitation(aliceFile, "crab")
		Expect(err).ToNot(BeNil())
	})

	Specify("non existant user store ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())
		var bad *client.User

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		err = bad.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).ToNot(BeNil())
	})

	Specify("non existant user load ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())
		var bad *client.User

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		_, err = bad.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())
	})

	Specify("non existant user append ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())
		var bad *client.User

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		err = bad.AppendToFile(aliceFile, []byte("garbage"))
		Expect(err).ToNot(BeNil())
	})

	Specify("non existant user revoke ", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword2)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword3)
		Expect(err).To(BeNil())
		var bad *client.User

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		err = bad.RevokeAccess(aliceFile, "garbage")
		Expect(err).ToNot(BeNil())
	})
	Specify("Malitcious append file struct ", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		before := userlib.DatastoreGetMap()
		beforeKeys := make([]uuid.UUID, 0, len(before))
		for u := range before {
			beforeKeys = append(beforeKeys, u)
		}

		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).To(BeNil())
		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		for _, v1 := range keys {
			contained := false

			for _, v2 := range beforeKeys {
				userlib.DebugMsg("before %v, after %v ", v1, v2)
				userlib.DebugMsg("ENTERED ONCE")
				if v1 == v2 {
					contained = true
				}
			}
			if !contained {
				userlib.DebugMsg("ENTERED ONCE")
				userlib.DatastoreSet(v1, []byte("garbage"))
			}
		}
		err = alice.AppendToFile("grapes", []byte("grapes"))
		Expect(err).ToNot(BeNil())
	})
	Specify("Malitcious store file struct ", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())
		before := userlib.DatastoreGetMap()
		beforeKeys := make([]uuid.UUID, 0, len(before))
		for u := range before {
			beforeKeys = append(beforeKeys, u)
		}

		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).To(BeNil())
		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		for _, v1 := range keys {
			contained := false

			for _, v2 := range beforeKeys {
				userlib.DebugMsg("before %v, after %v ", v1, v2)
				userlib.DebugMsg("ENTERED ONCE")
				if v1 == v2 {
					contained = true
				}
			}
			if !contained {
				userlib.DebugMsg("ENTERED ONCE")
				userlib.DatastoreSet(v1, []byte("garbage"))
			}
		}
		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).ToNot(BeNil())
	})

	// Specify("Malitcious init user ", func() {
	// 	userlib.DebugMsg("Initializing users Alice")
	// 	alice, err = client.InitUser("alice", defaultPassword)
	// 	err = alice.StoreFile("grapes", []byte("grapes"))
	// 	Expect(err).To(BeNil())

	// 	before := userlib.DatastoreGetMap()
	// 	beforeKeys := make([]uuid.UUID, 0, len(before))
	// 	for u := range before {
	// 		beforeKeys = append(beforeKeys, u)
	// 	}

	// 	bob, err = client.InitUser("bob", defaultPassword)
	// 	Expect(err).To(BeNil())
	// 	p := userlib.DatastoreGetMap()
	// 	keys := make([]uuid.UUID, 0, len(p))
	// 	for u := range p {
	// 		keys = append(keys, u)
	// 	}
	// 	for _, v1 := range keys {
	// 		contained := false

	// 		for _, v2 := range beforeKeys {
	// 			userlib.DebugMsg("before %v, after %v ", v1, v2)
	// 			userlib.DebugMsg("ENTERED ONCE")
	// 			if v1 == v2 {
	// 				contained = true
	// 			}
	// 		}
	// 		if !contained {
	// 			userlib.DebugMsg("ENTERED ONCE")
	// 			userlib.DatastoreSet(v1, []byte("garbage"))
	// 		}
	// 	}
	// 	err = alice.StoreFile("grapes", []byte("grapes"))
	// 	Expect(err).To(BeNil())
	// 	err = bob.StoreFile("grapes", []byte("grapes"))
	// 	Expect(err).ToNot(BeNil())
	// 	_, err = client.GetUser("bob", defaultPassword)
	// 	Expect(err).ToNot(BeNil())
	// })

	Specify("Delete Invite Struct", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		userlib.DebugMsg("Initializing users Bob")
		bob, err = client.InitUser("bob", defaultPassword2)

		err = alice.StoreFile(aliceFile, []byte("grapes"))
		Expect(err).To(BeNil())

		Expect(err).To(BeNil())
		before := userlib.DatastoreGetMap()
		beforeKeys := make([]uuid.UUID, 0, len(before))
		for u := range before {
			beforeKeys = append(beforeKeys, u)
		}

		invt, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		p := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p))
		for u := range p {
			keys = append(keys, u)
		}
		for _, v1 := range keys {
			contained := false
			for _, v2 := range beforeKeys {
				if v1 == v2 {
					contained = true
				}
			}
			if !contained {
				userlib.DatastoreSet(v1, []byte("garbage"))
			}
		}
		// Expect that Bob's invitation was destroyed
		bob.AcceptInvitation("alice", invt, bobFile)
		Expect(err).ToNot(BeNil())
		_, err = bob.LoadFile(bobFile)
		Expect(err).ToNot(BeNil())

		// Expect other behavior to still work
		_, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		_, err = client.GetUser("bob", defaultPassword2)
		Expect(err).To(BeNil())
		err = bob.StoreFile(bobFile, []byte(contentOne))
		Expect(err).To(BeNil())
	})

	
		// Specify("Test that file chunks move upon revoke", func() {
		// 	userlib.DebugMsg("Initializing users Alice")
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	userlib.DebugMsg("Initializing users Bob")
		// 	bob, err = client.InitUser("bob", defaultPassword2)

		// 	// Steps:
		// 	// take snapshot
		// 	// store small file
		// 	// take snapshot (identify file struct and new chunk)
		// 	// share with user
		// 	// revoke user
		// 	// overwrite file struct with nonsense
		// 	// check that alice can still store file (bc file struct has been moved)
		// 	// fail test if not

		// 	// From OH TODO:
		// 	// append should not scale with number of files, number of users, etc.
		// 	// improve append to not depending on chunksize
		// 	// try malicious tests with swapping data around instead of just overwrite garbage/delete
		// 	//	 (ie check issue where implementation uses same signing key for all invitations/ same key for all users structs/ etc)

		// 	err = alice.StoreFile(aliceFile, []byte("grapes"))
		// 	Expect(err).To(BeNil())

		// 	Expect(err).To(BeNil())
		// 	before := userlib.DatastoreGetMap()
		// 	beforeKeys := make([]uuid.UUID, 0, len(before))
		// 	for u := range before {
		// 		beforeKeys = append(beforeKeys, u)
		// 	}

		// 	invt, err := alice.CreateInvitation(aliceFile, "bob")
		// 	Expect(err).To(BeNil())

		// 	p := userlib.DatastoreGetMap()
		// 	keys := make([]uuid.UUID, 0, len(p))
		// 	for u := range p {
		// 		keys = append(keys, u)
		// 	}
		// 	for _, v1 := range keys {
		// 		contained := false
		// 		for _, v2 := range beforeKeys {
		// 			if v1 == v2 {
		// 				contained = true
		// 			}
		// 		}
		// 		if !contained {
		// 			userlib.DatastoreSet(v1, []byte("garbage"))
		// 		}
		// 	}
		// 	// Expect that Bob's invitation was destroyed
		// 	bob.AcceptInvitation("alice", invt, bobFile)
		// 	Expect(err).ToNot(BeNil())
		// 	_, err = bob.LoadFile(bobFile)
		// 	Expect(err).ToNot(BeNil())

		// 	// Expect other behavior to still work
		// 	_, err = alice.LoadFile("grapes")
		// 	Expect(err).To(BeNil())
		// 	_, err = client.GetUser("bob", defaultPassword2)
		// 	Expect(err).To(BeNil())
		// 	err = bob.StoreFile(bobFile, []byte(contentOne))
		// 	Expect(err).To(BeNil())
		// })
	
	
	Specify("Swap User (same password)", func() {
		// Snapshot
		before := userlib.DatastoreGetMap()
		beforeKeys := make([]uuid.UUID, 0, len(before))
		for u := range before {
			beforeKeys = append(beforeKeys, u)
		}

		// Init Alice
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		// Snapshot
		p1 := userlib.DatastoreGetMap()
		keys := make([]uuid.UUID, 0, len(p1))
		for u := range p1 {
			keys = append(keys, u)
		}

		// Init Bob
		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		// Snapshot
		p2 := userlib.DatastoreGetMap()
		keys2 := make([]uuid.UUID, 0, len(p2))
		for u := range p2 {
			keys2 = append(keys2, u)
		}

		// Alice Store File
		err = alice.StoreFile("grapes", []byte("grapes"))
		Expect(err).To(BeNil())

		// Swap the users in Data store (over write bob with alice)
		//get alice uuid
		aliceUserUUID := uuid.Nil
		bobUserUUID := uuid.Nil
		for v, _ := range p1 {
			ok := before[v]
			if ok != nil {
				aliceUserUUID = v
			}
		}
		for v, _ := range p2 {
			ok := p1[v]
			if ok != nil {
				bobUserUUID = v
			}
		}

		aliceUserData, found := userlib.DatastoreGet(aliceUserUUID)
		Expect(found).To(BeTrue())
		userlib.DatastoreSet(bobUserUUID, aliceUserData)

		_, err = bob.LoadFile("grapes")
		Expect(err).ToNot(BeNil())

		err = bob.AppendToFile("grapes", []byte("grapes"))
		Expect(err).ToNot(BeNil())

		bob, err = client.GetUser("bob", defaultPassword)
		//userlib.DebugMsg("The userdata bob: %v", bob)
		//userlib.DebugMsg("The userdata alice: %v", alice)
		Expect(err).ToNot(BeNil())

		err = bob.StoreFile("grapes", []byte("grapes"))
		Expect(err).ToNot(BeNil())

		_, err = bob.LoadFile("grapes")
		Expect(err).ToNot(BeNil())

		err = bob.AppendToFile("grapes", []byte("grapes"))
		Expect(err).ToNot(BeNil())
	})

	Specify("Swap Files ", func() {
	})

	Specify("Swap Invitations ", func() {
	})
	
})



// Helper Function to Generate random bytes
func genBytes(size uint32) []byte {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		userlib.DebugMsg("error while generating random string: %s", err)
		return nil
	}
	return bytes
}

func pDiffBounded(bw1 float64, bw2 float64, bound float64) bool {
	diff := float64(bw1 - bw2)
	if diff < 0 {
		diff = -1 * diff
	}
	avg := float64(bw1+bw2) / 2.0
	pdiff := (diff / avg) * 100.0

	userlib.DebugMsg("Bw1 %v Bw2 %v", bw1, bw2)
	userlib.DebugMsg("This is the percent difference: %v", pdiff)
	return pdiff < bound
}
