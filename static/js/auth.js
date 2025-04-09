import { 
  getAuth, 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword, 
  signInWithPopup, 
  GoogleAuthProvider,
  onAuthStateChanged,
  signOut
} from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js';

/**
 * Firebase authentication functions
 */
export class FirebaseAuthService {
  constructor(app) {
    this.auth = getAuth(app);
    this.googleProvider = new GoogleAuthProvider();
  }
  
  /**
   * Checks if a user is currently logged in
   * @returns {Promise<Object|null>} User object if logged in, null otherwise
   */
  getCurrentUser() {
    return new Promise((resolve, reject) => {
      const unsubscribe = onAuthStateChanged(
        this.auth,
        (user) => {
          unsubscribe();
          resolve(user);
        },
        reject
      );
    });
  }
  
  /**
   * Sign in with email and password
   * @param {string} email User email
   * @param {string} password User password
   * @returns {Promise<Object>} User credentials
   */
  async loginWithEmail(email, password) {
    try {
      return await signInWithEmailAndPassword(this.auth, email, password);
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  }
  
  /**
   * Register with email and password
   * @param {string} email User email
   * @param {string} password User password
   * @returns {Promise<Object>} User credentials
   */
  async registerWithEmail(email, password) {
    try {
      return await createUserWithEmailAndPassword(this.auth, email, password);
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  }
  
  /**
   * Sign in with Google
   * @returns {Promise<Object>} User credentials
   */
  async loginWithGoogle() {
    try {
      return await signInWithPopup(this.auth, this.googleProvider);
    } catch (error) {
      console.error('Google sign-in error:', error);
      throw error;
    }
  }
  
  /**
   * Sign out current user
   * @returns {Promise<void>}
   */
  async logout() {
    try {
      await signOut(this.auth);
      // Also clear session on server
      return fetch('/api/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } catch (error) {
      console.error('Logout error:', error);
      throw error;
    }
  }
  
  /**
   * Get ID token for current user
   * @returns {Promise<string>} ID token
   */
  async getIdToken() {
    const user = this.auth.currentUser;
    if (!user) {
      throw new Error('No user logged in');
    }
    return user.getIdToken();
  }
  
  /**
   * Verify ID token with server
   * @param {string} idToken Firebase ID token
   * @returns {Promise<Object>} Server response
   */
  async verifyTokenWithServer(idToken) {
    try {
      const response = await fetch('/api/verify-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ idToken })
      });
      
      if (!response.ok) {
        throw new Error('Failed to verify token with server');
      }
      
      return response.json();
    } catch (error) {
      console.error('Token verification error:', error);
      throw error;
    }
  }
}
