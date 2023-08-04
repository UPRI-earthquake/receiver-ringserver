## Prerequisites
1. Make sure you have build tools installed. This depends on the system you're using. We're using Ubuntu linux in our dev env. 
    ```bash
    sudo apt install gcc make autoconf libtool
    ```
2. If you don't have these curl dependencies yet, install them as well. You can verify once their installed via: `dpkg -L <package-name>`
    ```bash
    sudo apt install libssl-dev zlib1g-dev
    ```
3. This RingServer is dependent on the [earthquake-hub-backend](https://github.com/UPRI-earthquake/earthquake-hub-backend) as its AuthServer. Make sure that you also have that running on your development system.

## Setting Up The Repository On Your Local Machine
1. Clone the repository
    ```bash
    git clone git@github.com:UPRI-earthquake/receiver-ringserver.git
    ```
2. Build the source code, go into the receiver-ringserver directory and run `make`. This should create a `ringserver` executable in the same directory.
3. Create necessary files & folders
   1. Ring directory
      ```bash
      mkdir ring
      ```
   2. Auth directory
      ```bash
      mkdir auth
      ```
  3. Acquire a _brgy_ account secret key from [earthquake-hub-backend](https://github.com/UPRI-earthquake/earthquake-hub-backend) and paste the string in file named `auth/secret.key` (there should be no spaces whatsoever).
5. Edit configuration in (doc/ring.conf)[./doc/ring.conf]. It has sensible defaults but you may want to change these in particular:
    1. `AuthServer` - HTTP endpoint for token verification on the Authentication Server
    2. `ListenPort` - TCP port where RingServer should be accessible on
    3. `RingSize` - Size of the ring buffer data structure (1 Gig by default).
6. Run the server with verbosity=2. You may check `localhost:16000/status` on your browser to check if the server is running correctly.
   ```bash
      ./ringserver -vv doc/ring.conf
   ```
