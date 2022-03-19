# FF-PWD
ff-pwd is a readonly password store that is able to read and store passwords as
exported from firefox in CSV format. The main reason for its inception is for me
to be able to look up passwords on-the-go on my ubports phone, but I suppose it
could be useful for any device that does not have a native firefox sync client
or firefox browser to sync and store login information.

## What does it do?
ff-pwd imports password CSVs and stores them in a SHA256 symmetrically encrypted
file for which you choose the passphrase yourself. After importing, you can use
`ff-pwd find` to search for passwords through a text-based fuzzy selection
UI. After selecting a password, it will be printed in plaintext to the standard
output of the program. While this is not optimal, I have not been able to find a
portable way (read: a way that does not require cgo) to access the system
clipboard on a ubports device so yanking directly to the clipboard is not yet an
option.

## Security implications
I am by no means a security expert and have written this untested, kind of messy
piece of software in just one day. I have superficial knowledge of encryption,
so the encryption implementation is very barebones and may not be on the
forefront of encryption best practices. This being said having the file be
encrypted is better than having it be not at all encrypted. The software being
fairly non-standard and running on a non-standard operating system combined with
the encryption make for a reasonably secure way to store passwords in my case at
any rate.

If there are any mistakes or encryption mishaps going on in the code, please do
share them with me as I would be interested to learn more and improve the
security of the program in the process.

## Installation and usage
The easiest way to get this software going is on a desktop computer with golang
and firefox installed on it:

1. Open a terminal and clone the repository `git clone git@github.com/hugot/ff-pwd.git`
2. Change directory to the repository and build the software `cd ff-pwd; go build .`
3. Open your firefox browser, navigate to `about:logins`, click on the
   three-dotted menu button in the top right corner of the page and click on
   "Export logins". Save the file as ~/Downloads/logins.csv.
4. In your terminal, type `./ff-pwd import` to import the passwords and go
   through the initial setup steps.
5. Now compile ff-pwd for arm64 using `GOARCH=arm64 go build .`
6. Move the ff-pwd file over to your ubports device. I use `scp ./ff-pwd
   phablet@[phablet-ip]:/home/phablet/bin/ff-pwd` for this because I have ssh
   enabled on my device.
7. Now move the data file ~/.config/ff-pwd/data.json over to the same location
   on the ubports device. `ssh phablet@[phablet-ip] mkdir -p
   /home/phablet/.config/ff-pwd; scp ~/.config/ff-pwd/data.json
   phablet@[phablet-ip]:/home/phablet/.config/ff-pwd/data.json`.
8. To search for passwords on your device you can now run `ff-pwd find` from the
   terminal app.

It isn't optimal, to keep the password database on your phone up to date you'll
need to import it every once in a while and sync it over to your phone. It might
be worth it to create a nextcloud sync folder on your device to make the process
of sending the file over a bit more streamlined. There is currently no way to
automate the firefox password export.
