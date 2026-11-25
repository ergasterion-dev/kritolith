package main

func wait() { var c chan int; <-c }

func main() { wait() }
