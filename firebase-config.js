/* Google sign-in, people search and moderation for Voxelify (optional).
   Leave it as it is and profiles work only on this device.
   To turn it on, create a free Firebase project and paste its web config below
   (step by step: README → "Google sign-in (optional)"). These keys are public by design: they only identify the project;
   the Firestore rules from the README decide who can change what. */
window.VX_FIREBASE = {
  apiKey: "AIzaSyDIrFFuT5JXkkKmiHxgYPvAL0BDsSE4GEc",
  authDomain: "v0xelify.firebaseapp.com",
  projectId: "v0xelify",
  appId: "1:314972614015:web:2c8d828b049c0008637e4a"
};
/* The owner of the site: this Google e-mail gets the admin tools (check marks, SCAM, bans).
   Put the same e-mail into the Firestore rules (README), because the rules are what really protects it. */
window.VX_OWNER_EMAIL = "wisperplay2010@gmail.com";
/* Example:
window.VX_FIREBASE = {
  apiKey: "AIza...",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project",
  appId: "1:1234567890:web:abcdef"
};
window.VX_OWNER_EMAIL = "you@gmail.com";
*/
