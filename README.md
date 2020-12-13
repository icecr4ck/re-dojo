# RE-Dojo

Blog about reverse engineering, binary analysis and CTF challenges.

## How to write a new post and publish it

1. Install `hugo` (see [here](https://gohugo.io/getting-started/installing/)) and verify the installation with `hugo version`.
2. Clone this repository (don't forget the `--recursive` flag to get the submodules as well).
```
git clone --recursive https://github.com/icecr4ck/re-dojo.git
```
3. Create a new post.
```
hugo new write-ups/YYYY-MM-DD-name-of-the-post.md
```
4. Edit the newly created post file and fix the metadata fields as necessary (author, title, subtitle...).
5. If you need to add images, copy them to `static/images`.
6. Go to the root of the repository and start the server.
```
hugo server
```
7. Go to `http://localhost:1313/` and check if everything looks fine.
8. If necessary, set the remote URL as follows.
```
git remote set-url origin git@github.com:RE-Dojo/re-dojo.github.io.git
```
9. Run the script `deploy.sh` and enjoy!

## How to add a new author

1. Edit the file `data/author.toml`
2. Add a new author using the following template:
```
[superman]
name = "Clark Kent"
uri = "https://www.superman.com"
twitter = "superman"
image = "images/author/superman.png"
email = "superman@earth.com"
```
3. Add your profile picture to `static/images/author/`
4. Add the author field to your blog posts
```
+++
[...]
author = "superman"
[...]
+++
```

## Resources

* https://gohugo.io/getting-started/quick-start/
* https://gohugo.io/hosting-and-deployment/hosting-on-github/
* https://github.com/marketempower/axiom
