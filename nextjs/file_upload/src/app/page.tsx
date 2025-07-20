'use client';

import { useState, useEffect } from 'react';

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState<{filename: string, originalName: string, size: number}[]>([]);
  const [availableFiles, setAvailableFiles] = useState<{filename: string, originalName: string, size: number, uploadedAt: string}[]>([]);
  const [message, setMessage] = useState('');

  const fetchAvailableFiles = async () => {
    try {
      const response = await fetch('/api/files');
      const data = await response.json();
      if (response.ok) {
        setAvailableFiles(data.files);
      }
    } catch {
      console.log('Failed to fetch available files');
    }
  };

  useEffect(() => {
    fetchAvailableFiles();
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setMessage('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();

      if (response.ok) {
        setMessage('File uploaded successfully!');
        setUploadedFiles(prev => [...prev, result]);
        setFile(null);
        (e.target as HTMLFormElement).reset();
        fetchAvailableFiles();
      } else {
        setMessage(`Error: ${result.error}`);
      }
    } catch {
      setMessage('Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleDownload = async (filename: string) => {
    try {
      const response = await fetch(`/api/download?filename=${filename}`);
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      } else {
        setMessage('Download failed');
      }
    } catch {
      setMessage('Download failed');
    }
  };

  return (
    <main className="container mx-auto p-8 max-w-2xl">
      <h1 className="text-3xl font-bold mb-8">File Upload & Download</h1>
      
      <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Upload File</h2>
        <form onSubmit={handleUpload} className="space-y-4">
          <div>
            <input
              type="file"
              onChange={handleFileChange}
              className="block w-full text-sm text-gray-500
                file:mr-4 file:py-2 file:px-4
                file:rounded-full file:border-0
                file:text-sm file:font-semibold
                file:bg-blue-50 file:text-blue-700
                hover:file:bg-blue-100"
            />
          </div>
          <button
            type="submit"
            disabled={!file || uploading}
            className="bg-blue-500 hover:bg-blue-700 disabled:bg-gray-400 
              text-white font-bold py-2 px-4 rounded"
          >
            {uploading ? 'Uploading...' : 'Upload'}
          </button>
        </form>
        
        {message && (
          <div className={`mt-4 p-3 rounded ${
            message.includes('Error') || message.includes('failed') 
              ? 'bg-red-100 text-red-700' 
              : 'bg-green-100 text-green-700'
          }`}>
            {message}
          </div>
        )}
      </div>

      <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Available Downloads</h2>
        {availableFiles.length === 0 ? (
          <p className="text-gray-500">No files available for download</p>
        ) : (
          <div className="space-y-2">
            {availableFiles.map((file, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                <div>
                  <p className="font-medium">{file.originalName}</p>
                  <p className="text-sm text-gray-600">
                    Size: {(file.size / 1024).toFixed(2)} KB | 
                    Uploaded: {new Date(file.uploadedAt).toLocaleDateString()}
                  </p>
                </div>
                <button
                  onClick={() => handleDownload(file.filename)}
                  className="bg-green-500 hover:bg-green-700 text-white font-bold py-1 px-3 rounded text-sm"
                >
                  Download
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {uploadedFiles.length > 0 && (
        <div className="bg-white shadow-lg rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Uploaded Files</h2>
          <div className="space-y-2">
            {uploadedFiles.map((file, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                <div>
                  <p className="font-medium">{file.originalName}</p>
                  <p className="text-sm text-gray-600">Size: {(file.size / 1024).toFixed(2)} KB</p>
                </div>
                <button
                  onClick={() => handleDownload(file.filename)}
                  className="bg-green-500 hover:bg-green-700 text-white font-bold py-1 px-3 rounded text-sm"
                >
                  Download
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </main>
  );
}
