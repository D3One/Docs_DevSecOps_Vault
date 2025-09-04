FROM nginx:latest  # VIOLATION! Uses the 'latest' tag.
COPY . /usr/share/nginx/html

# VIOLATION! No USER instruction defined to switch from root.
CMD ["nginx", "-g", "daemon off;"]
