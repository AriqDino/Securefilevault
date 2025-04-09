/**
 * File upload functionality with progress tracking
 */
export class FileUploadService {
  constructor(csrfToken) {
    this.csrfToken = csrfToken;
  }
  
  /**
   * Upload a file with progress tracking
   * @param {File} file File to upload
   * @param {string} description File description
   * @param {Function} onProgress Progress callback
   * @param {Function} onSuccess Success callback
   * @param {Function} onError Error callback
   */
  uploadFile(file, description, onProgress, onSuccess, onError) {
    // Create FormData
    const formData = new FormData();
    formData.append('file', file);
    formData.append('description', description);
    formData.append('csrf_token', this.csrfToken);
    
    // Create XHR
    const xhr = new XMLHttpRequest();
    
    // Setup progress tracking
    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) {
        const percentComplete = Math.round((e.loaded / e.total) * 100);
        onProgress(percentComplete);
      }
    });
    
    // Setup completion handler
    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const response = JSON.parse(xhr.responseText);
          if (response.success) {
            onSuccess(response);
          } else {
            onError(response.error || 'Upload failed');
          }
        } catch (e) {
          onError('Invalid response from server');
        }
      } else {
        let errorMsg = 'Upload failed';
        try {
          const response = JSON.parse(xhr.responseText);
          errorMsg = response.error || errorMsg;
        } catch (e) {}
        
        onError(errorMsg);
      }
    });
    
    // Setup error handler
    xhr.addEventListener('error', () => {
      onError('Network error occurred');
    });
    
    // Setup abort handler
    xhr.addEventListener('abort', () => {
      onError('Upload aborted');
    });
    
    // Send request
    xhr.open('POST', '/api/upload');
    xhr.send(formData);
    
    // Return the XHR object to allow abortion if needed
    return xhr;
  }
  
  /**
   * Validate file before upload
   * @param {File} file File to validate
   * @returns {Object} Validation result
   */
  validateFile(file) {
    const result = {
      valid: true,
      message: ''
    };
    
    // Check if file is selected
    if (!file) {
      result.valid = false;
      result.message = 'No file selected';
      return result;
    }
    
    // Check file size (max 16MB)
    const maxSize = 16 * 1024 * 1024; // 16MB
    if (file.size > maxSize) {
      result.valid = false;
      result.message = 'File size exceeds 16MB limit';
      return result;
    }
    
    // Check file extension
    const allowedExtensions = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'];
    const extension = file.name.split('.').pop().toLowerCase();
    
    if (!allowedExtensions.includes(extension)) {
      result.valid = false;
      result.message = 'File type not allowed';
      return result;
    }
    
    return result;
  }
}
