# RE-Dojo

Blog about reverse engineering and CTF challenges.

## How to write a new post and publish it

1. Install `hugo` (see [here](https://gohugo.io/getting-started/installing/)) and verify the installation with `hugo version`.
2. Clone this repository (don't forget the `--recursive` flag to get the submodules as well).
```
git clone --recursive https://github.com/icecr4ck/re-dojo.git
```
3. Create a new post.
```
hugo new post/YYYY-MM-DD-name-of-the-post.md
```
4. Edit the newly created post file and fix the metadata fields as necessary (author, title, tags, etc.).
5. If you need to add images, copy them to `static/images`.
6. Go to the root of the repository and start the server.
```
hugo server
```
7. Go to [http://localhost:1313/](http://localhost:1313) and check if everything looks fine.
8. If necessary, set the remote URL of the public repository as follows.
```
cd public
git remote set-url origin git@github.com:RE-Dojo/re-dojo.github.io.git
```
9. Go back to the root of the repository and run the script `deploy.sh`.

## How to add a new author

1. Create a new file at `data/authors/john-doe.yml` (replace the filename accordingly)
2. Edit the file using the following template:
```
name: John Doe
email: john@example.com
```
3. Add the author field to your blog posts
```
[...]
authors:
  - john-doe 
[...]
```

## Resources

* https://gohugo.io/getting-started/quick-start/
* https://gohugo.io/hosting-and-deployment/hosting-on-github/
* https://hugo-geekblog.geekdocs.de/
* https://github.com/marketempower/axiom
