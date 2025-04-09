/**
 * Dashboard functionality for managing files
 */
export class DashboardService {
  constructor(csrfToken) {
    this.csrfToken = csrfToken;
  }
  
  /**
   * Fetch files for the current user
   * @returns {Promise<Array>} List of files
   */
  async fetchFiles() {
    try {
      const response = await fetch('/api/files');
      
      if (!response.ok) {
        throw new Error('Failed to fetch files');
      }
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.error || 'Unknown error');
      }
      
      return data.files;
    } catch (error) {
      console.error('Error fetching files:', error);
      throw error;
    }
  }
  
  /**
   * Delete a file
   * @param {number} fileId File ID to delete
   * @returns {Promise<Object>} Server response
   */
  async deleteFile(fileId) {
    try {
      const response = await fetch(`/api/files/${fileId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ csrf_token: this.csrfToken })
      });
      
      if (!response.ok) {
        throw new Error('Failed to delete file');
      }
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.error || 'Unknown error');
      }
      
      return data;
    } catch (error) {
      console.error('Error deleting file:', error);
      throw error;
    }
  }
  
  /**
   * Get detailed information about a file
   * @param {number} fileId File ID
   * @returns {Promise<Object>} File information
   */
  async getFileDetails(fileId) {
    try {
      const response = await fetch(`/api/files/${fileId}`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch file details');
      }
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.error || 'Unknown error');
      }
      
      return data.file;
    } catch (error) {
      console.error('Error fetching file details:', error);
      throw error;
    }
  }
  
  /**
   * Format file size for display
   * @param {number} bytes File size in bytes
   * @returns {string} Formatted file size
   */
  formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    else if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
    else return (bytes / 1073741824).toFixed(2) + ' GB';
  }
  
  /**
   * Format date for display
   * @param {string} dateString Date string
   * @returns {string} Formatted date
   */
  formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  }
  
  /**
   * Get file icon class based on file extension
   * @param {string} filename Filename with extension
   * @returns {string} Font Awesome icon class
   */
  getFileIconClass(filename) {
    const fileIcons = {
      'pdf': 'fa-file-pdf',
      'doc': 'fa-file-word',
      'docx': 'fa-file-word',
      'xls': 'fa-file-excel',
      'xlsx': 'fa-file-excel',
      'txt': 'fa-file-alt',
      'jpg': 'fa-file-image',
      'jpeg': 'fa-file-image',
      'png': 'fa-file-image',
      'gif': 'fa-file-image',
      'default': 'fa-file'
    };
    
    const extension = filename.split('.').pop().toLowerCase();
    return fileIcons[extension] || fileIcons.default;
  }
  
  /**
   * Get scan status badge HTML
   * @param {Object} file File object
   * @returns {string} Badge HTML
   */
  getScanStatusBadge(file) {
    if (!file.is_scanned) {
      return '<span class="badge bg-warning text-dark"><i class="fas fa-hourglass-half me-1"></i> Pending</span>';
    } else if (file.is_safe) {
      return '<span class="badge bg-success"><i class="fas fa-shield-alt me-1"></i> Clean</span>';
    } else if (file.is_safe === false) { // Explicitly false
      return '<span class="badge bg-danger"><i class="fas fa-virus me-1"></i> Malicious</span>';
    } else {
      return '<span class="badge bg-secondary"><i class="fas fa-question-circle me-1"></i> Unknown</span>';
    }
  }
  
  /**
   * Check if file can be downloaded (is safe)
   * @param {Object} file File object
   * @returns {boolean} True if file can be downloaded
   */
  canDownload(file) {
    return file.is_safe !== false && file.file_path !== null;
  }
}
