FROM node:16-alpine

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker cache
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install

# Copy the entire frontend codebase
COPY . .

# Build the app for production
RUN npm run build --production

# Expose the port the app runs on
EXPOSE 3000

# Start the app
CMD ["npm", "start"]
