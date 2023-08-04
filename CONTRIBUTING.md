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
4. Acquire a _brgy_ account secret key from [earthquake-hub-backend](https://github.com/UPRI-earthquake/earthquake-hub-backend). Send a POST request to http://172.22.0.3:5000/accounts/authenticate with the following request body:
    ```json
    {
        "username": "brgy",
        "password": "testpassword",
        "role": "brgy"
    }
    ```
5. Paste the string in file named `auth/secret.key` (there should be no spaces whatsoever).
6. Edit configuration in (doc/ring.conf)[./doc/ring.conf]. It has sensible defaults but you may want to change these in particular:
    1. `AuthServer` - HTTP endpoint for token verification on the Authentication Server
    2. `ListenPort` - TCP port where RingServer should be accessible on
    3. `RingSize` - Size of the ring buffer data structure (1 Gig by default).
7. Run the server with verbosity=2.
   ```bash
      ./ringserver -vv doc/ring.conf
   ```
8. You may verify if the ringserver is working correctly using any of the following:
   - check `localhost:16000/status` on your browser
   - `./dalitool -p <ringserver-address>` (ie localhost:16000)
   - `./slinktool -S <net_sta> <ringserver-address>` (ie net_sta = GE_TOLI2)  
   See more information in [slinktool](https://github.com/EarthScope/slinktool) or [dalitool](https://github.com/iris-edu/dalitool) in their respective repositories.
