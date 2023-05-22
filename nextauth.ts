import NextAuth, { SessionStrategy } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import getUserDetails from "@/src/utils/getUserDetails";

export default NextAuth({
  secret: process.env.NEXTAUTH_SECRET,
  session: {
    // An encrypted JWT (JWE) stored in the session cookie.
    strategy: "jwt" as SessionStrategy,
    // Seconds - How long until an idle session expires and is no longer valid.
    maxAge: 3600,
  },
  jwt: {
    // The maximum age of the NextAuth.js issued JWT in seconds.
    maxAge: 3600,
  },
  providers: [
    CredentialsProvider({
      // The name to display on the sign in form (e.g. 'Sign in with...')
      name: "Credentials",
      // The credentials is used to generate a suitable form on the sign in page.
      // You can specify whatever fields you are expecting to be submitted.
      // e.g. domain, username, password, 2FA token, etc.
      // You can pass any HTML attribute to the <input> tag through the object.
      credentials: {
        username: {
          label: "Username",
          type: "text",
          placeholder: "Tenant Name",
        },
        password: {
          label: "Password",
          type: "password",
          placeholder: "Password",
        },
      },
      async authorize(credentials, req) {
        // Provide in this function own logic that takes the credentials
        // submitted and returns an object representing a user or 
        // throw an error if the credentials are invalid.
        // e.g. return { id: 1, name: 'J Smith', email: 'jsmith@example.com' }
        // You can also use the `req` object to obtain additional parameters
        // (i.e., the request IP address)
        const username = credentials?.username;
        const password = credentials?.password;
        if (!username || !password) {
          throw new Error("Enter Username and Password");
        }
        const url: string = process.env.SERVER_URL + "/login.json";
        try {
          const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({username: username, password: password}),
          });
          const user = await response.json();
          // Check for response code 200 (OK) and return response object to the user
          if(response.ok && user) {
            return user;
          } else {
            // If server response code other than 200 (OK) an error will be
            // thrown containing an error message received from server
            // side under messageId field. Authorization will be rejected
            if (user && user.messageId.includes("usernameError")) {
              throw new Error("Please provide correct username value");
            }
            if (user && user.messageId.includes("invalidPasswordError")) {
              throw new Error("Please provide correct password value");
            }
            // By returning `null` authorization will be rejected. Either user object is absent or
            // messageId value is different from defined above all going to be
            // handed over as `CredentialsSignin` error.
            return null;
          }
        } catch (err) {
          // error logger implementation ?
          // Reject authorize callback with an Error thus the user will be sent to 
          // the error page with the error message as a query parameter
          if (typeof err === "string") {
            throw new Error(err.toUpperCase()) // `err` narrowed to string
          } else if (err instanceof Error) {
            throw new Error(err.message) // `err` narrowed to Error
          }
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // User object will be passed on initial signIn call where token will receive new fields
      if (user) {
        token.id = user.id;
        token.sessionId = user.message;
        if (user.id && user.message) {
          const userDetails = await getUserDetails(user.id, user.message);
          if (userDetails) {
            token.fullname = userDetails.fullname;
            token.email = userDetails.email;
            token.role = userDetails.role;
          }
        }
      }
      return token;
    },
    async session({ session, token }) {
      // Send properties `id`, `sessionId` to the client from the token 
      // Pass `fullname`, `email` and `role` from user's details  
      session.user = {
        id: token.id,
        sessionId: token.sessionId,
        fullname: token.fullname,
        email: token.email,
        role: token.role,
      }
      return session;
    },
  },
  pages: {
      // Specify URLs to be used if you want to create custom sign in, sign out and error pages.
      signIn: '/login',
      //signOut: '/auth/signout',
      //error: '/auth/error', // Error code passed in query string as ?error=
  },
});
