An easily clonable extension that can be used a base for building a new extension.

THe usual development enviroment is:

- Clone the myextension repo to your own repo
- Edit the cloned repos manifest to your details
- Install into LNbits
- Delete the cloned extensions folder in your LNbits install
- Create a symbolic link to the extensions folder, from the where you have pulled your extension `ln -s /where/you/cloned/myextension /your/lnbits/installl/lnbits/lnbits/extensions/`
