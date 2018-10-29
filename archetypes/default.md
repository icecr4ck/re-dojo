---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
author: {{ $.Param "author" }}
draft: true
---

