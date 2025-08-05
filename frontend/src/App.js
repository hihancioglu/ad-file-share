import React, { useState, useEffect } from 'react';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loggedIn, setLoggedIn] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [userFiles, setUserFiles] = useState([]);
  const [sharedLinks, setSharedLinks] = useState({});

  const handleLogin = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append("username", username);
    formData.append("password", password);

    const res = await fetch(`${API_URL}/login`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      setLoggedIn(true);
    } else {
      alert("Giriş başarısız: " + data.error);
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) return alert("Dosya seçiniz!");
    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("username", username);

    const res = await fetch(`${API_URL}/upload`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      alert("Yükleme başarılı: " + data.filename);
      setSelectedFile(null);
      fetchFiles();
    } else {
      alert("Hata: " + data.error);
    }
  };

  const fetchFiles = async () => {
    const formData = new FormData();
    formData.append("username", username);

    const res = await fetch(`${API_URL}/list`, {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    setUserFiles(data.files || []);
    setSharedLinks({});
  };

  const handleDownload = async (filename) => {
    const formData = new FormData();
    formData.append("username", username);
    formData.append("filename", filename);

    const res = await fetch(`${API_URL}/download`, {
      method: "POST",
      body: formData
    });

    if (res.ok) {
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(url);
    } else {
      alert("İndirme başarısız!");
    }
  };

  const handleDelete = async (filename) => {
    if (!window.confirm(`${filename} silinsin mi?`)) return;
    const formData = new FormData();
    formData.append("username", username);
    formData.append("filename", filename);

    const res = await fetch(`${API_URL}/delete`, {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      alert("Dosya silindi");
      fetchFiles();
    } else {
      alert("Silinemedi: " + data.error);
    }
  };

  const handleShare = async (filename) => {
    const formData = new FormData();
    formData.append("username", username);
    formData.append("filename", filename);

    const res = await fetch(`${API_URL}/share`, {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      setSharedLinks(prev => ({ ...prev, [filename]: `${API_URL}${data.link}` }));
    } else {
      alert("Paylaşım hatası: " + data.error);
    }
  };

  useEffect(() => {
    if (loggedIn) fetchFiles();
    // eslint-disable-next-line
  }, [loggedIn]);

  if (!loggedIn) {
    return (
      <div className="container">
        <h2>AD Girişi</h2>
        <form onSubmit={handleLogin}>
          <input
            placeholder="Kullanıcı adı"
            value={username}
            onChange={e => setUsername(e.target.value)}
            className="text-input"
          /><br />
          <input
            placeholder="Şifre"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            className="text-input"
          /><br />
          <button type="submit" className="btn">Giriş</button>
        </form>
      </div>
    );
  }

  return (
    <div className="container">
      <h2>Dosya Yükle</h2>
      <form onSubmit={handleUpload}>
        <input type="file" onChange={e => setSelectedFile(e.target.files[0])} /><br /><br />
        <button type="submit" className="btn">Yükle</button>
      </form>
      <div className="file-section">
        <h3>Yüklediğiniz Dosyalar:</h3>
        <ul>
          {userFiles.map(file => (
            <li key={file} className="file-item">
              <span className="file-link" onClick={() => handleDownload(file)}>{file}</span>
              <button onClick={() => handleDelete(file)}>Sil</button>
              <button onClick={() => handleShare(file)}>Paylaş</button>
              {sharedLinks[file] && (
                <a href={sharedLinks[file]} target="_blank" rel="noopener noreferrer">
                  Link
                </a>
              )}
            </li>
          ))}
        </ul>
        <button className="btn" onClick={() => setLoggedIn(false)}>Çıkış</button>
      </div>
    </div>
  );
}

export default App;
