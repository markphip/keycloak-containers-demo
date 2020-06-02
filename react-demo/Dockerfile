# pull base image
FROM node:13.12.0-alpine

# set working directory
WORKDIR /app

# install app dependencies
COPY react-demo/ ./
RUN yarn install

# start app
CMD ["yarn", "start"]