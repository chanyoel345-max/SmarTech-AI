
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

const firebaseConfig = {
apiKey: "AIzaSyB4L4dgEAIHvX_KmkCz6tZXMGqX3JIclbQ",
authDomain: "smartech-ai.firebaseapp.com",
projectId: "smartech-ai",
storageBucket: "smartech-ai.firebasestorage.app",
messagingSenderId: "796151675038",
appId: "1:796151675038:web:9567ae19747ea56d39238f",
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
