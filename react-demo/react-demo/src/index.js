import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';
import Keycloak from 'keycloak-js';

let keycloak = Keycloak('./resources/keycloak.json');
keycloak.init({
  onLoad: 'check-sso',
  checkLoginIFrame: false
}).success((auth) => {
  if (auth) {
    console.info("Pre uthenticated via SSO");
  } else {
    console.info("Not authenticated upon loading");
  }

  ReactDOM.render(
    <React.StrictMode>
      <App isAuthenticated={auth} keycloak={keycloak} />
    </React.StrictMode>,
    document.getElementById('root')
  );

  // If you want your app to work offline and load faster, you can change
  // unregister() to register() below. Note this comes with some pitfalls.
  // Learn more about service workers: https://bit.ly/CRA-PWA
  serviceWorker.unregister();

  localStorage.setItem("react-token", keycloak.token);
  localStorage.setItem("react-refresh-token", keycloak.refreshToken);

  setTimeout(() => {
    keycloak.updateToken(70).success((refreshed) => {
      if (refreshed) {
        console.debug('Token refreshed' + refreshed);
      } else {
        console.warn('Token not refreshed, valid for ' +
                     Math.round(keycloak.tokenParsed.exp + keycloak.timeSkew -
                                new Date().getTime() / 1000) + ' seconds');
      }
    }).error(() => {
      console.error('Failed to refresh token');
    });
  }, 60000)

}).error(() => {
  console.error("Authenticated Failed");
});
