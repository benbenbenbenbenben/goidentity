# goidentity

A simple Go module for managing user profile-based **EC keys**.

Like the thing AWS CLI does for credentials except with keys.

## Features

- Profile-based **EC key** management.
- Easy to use API for **generating and loading key pairs**.
- Simple JSON configuration format.
- Supports **ed25519, p256, p384, and p521 key types**.

## Installation

```bash
go get github.com/benbenbenbenbenben/goidentity
```

## Usage

```go
package main

import (
	"crypto"
	"fmt"
	"log"

	"github.com/benbenbenbenben/goidentity"
)

func main() {
	profileName := "default" // or get from user input, environment variable, etc.
	keyType := "ed25519"    // or get from user input, configuration, etc.

	// Create a new key pair for a profile
	profile, err := goidentity.NewCredentials("myawesomepackage").CreateKey(profileName, keyType)
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}
	fmt.Println("Created key pair for profile:", profileName)

	// Load an existing key pair
	loadedProfile, err := goidentity.NewCredentials("myawesomepackage").LoadKey(profileName)
	if err != nil {
		log.Fatalf("Failed to load key: %v", err)
	}
	fmt.Println("Loaded key pair for profile:", profileName)

	// Get the key pair
	privateKey, publicKey, err := goidentity.NewCredentials("myawesomepackage").GetKeyPair(profileName)
	if err != nil {
		log.Fatalf("Failed to get key pair: %v", err)
	}

	fmt.Printf("Private Key Type: %T\n", privateKey)
	fmt.Printf("Public Key Type: %T\n", publicKey)

	// ... use key pair ...
}
```

## Configuration

Keys are stored in a JSON file located at `~/.myawesomepackage/credentials.json` by default.
The file stores profiles as a JSON object:

```json
{
  "default": {
    "name": "default",
    "private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",
    "public_key": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
    "key_type": "ed25519"
  },
  "profile2": {
    "name": "profile2",
    "private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",
    "public_key": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
    "key_type": "p256"
  }
}
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bug reports or feature requests.

## License

[MIT](LICENSE)
