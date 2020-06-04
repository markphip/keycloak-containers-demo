import React from 'react';
//import logo from './logo.svg';
import './App.css';

function App({ isAuthenticated, keycloak }) {
  const serviceUrl = "https://flask-demo/api/v1";

  let [isLoggedIn, setLoggedIn] = React.useState(isAuthenticated);
  keycloak.onAuthLogout = () => {
    if (setLoggedIn) {
      setLoggedIn(false);
    }
  };

  let [message, setMessage] = React.useState(
    isLoggedIn ? 'User: ' + keycloak.tokenParsed['preferred_username'] : '');
  console.log('isLoggedIn:', isLoggedIn, message);

  function request(endpoint) {
    var req = function() {
      setMessage('');
      var req = new XMLHttpRequest();
      req.open('GET', serviceUrl + '/' + endpoint, true);

      if (keycloak.authenticated) {
        req.setRequestHeader('Authorization', 'Bearer ' + keycloak.token);
      }

      req.onreadystatechange = function () {
        if (req.readyState === 4) {
          if (req.status === 200) {
            setMessage('API Message: ' + req.responseText); // JSON.parse(req.responseText).message);
          } else if (req.status === 0) {
            setMessage(<span className="error">Request failed</span>);
          } else {
            setMessage(<span className="error">{ req.status } { req.statusText }</span>);
          }
        }
      };

      req.send();
    };

    if (keycloak.authenticated) {
      console.log('updating token')
      //keycloak.updateToken(30).success(req);
      keycloak.updateToken(30).success(() => {
        console.log('expires', new Date(keycloak.tokenParsed.exp * 1000));
        console.log('timeSkew', keycloak.timeSkew);
        console.log('tokenParsed', keycloak.tokenParsed);
        req();
      });
    } else {
      req();
    }
  }

  const loginButton = (
    <div id="not-authenticated" className="menu">
      <button name="loginBtn" onClick= { () => keycloak.login() }>Login</button>
    </div>
  );

  const isLoggedInButtons = (
    <div id="authenticated" className="menu">
      <button name="logoutBtn" onClick={ () => keycloak.logout() }>Logout</button>
      <button name="accountBtn" onClick={ () => keycloak.accountManagement() }>Account</button>
    </div>
  );

  const securedClickHandler = () => {
    if (isLoggedIn) {
      request('secured');
    } else {
      setMessage("Please log in");
    }
  }

  const adminClickHandler = () => {
    if (isLoggedIn) {
      request('admin');
    } else {
      setMessage("Please log in");
    }
  }

  return (
    <div className="wrapper">
      { isLoggedIn ? isLoggedInButtons : loginButton }

      <div className="content">
      <button name="publicBtn" onClick={ () => request('public') }>Invoke Public</button>
        <button name="securedBtn" ddisabled={ !isLoggedIn }
                onClick={ securedClickHandler }>Invoke Secured</button>
        <button name="adminBtn" ddisabled={ !isLoggedIn }
                onClick={ adminClickHandler }>Invoke Admin</button>
        <div className="message" id="message">{ message }</div>
      </div>
    </div>
  );
}

export default App;
