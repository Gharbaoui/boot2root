from manim import *

filename = "./turtle"

class Turtle:
    def __init__(self, current_pos, current_angle):
        self.current_pos = current_pos
        self.current_angle = np.radians(current_angle)

    def rotate(self, angle):
        self.current_angle += np.radians(angle)

    def advance(self, distance):
        distance = distance/100
        start_point = list(self.current_pos)
        self.current_pos += np.array([np.cos(self.current_angle), np.sin(self.current_angle), 0]) * distance
        end_point = self.current_pos
        return (start_point, end_point)

        

class Execute(Scene):
    def construct(self):
        with open(filename) as file:
            lines = [line for line in file]
        
        turtle = Turtle(np.array([0.0, 0.0, 0]), 90)

        self.add(Text("Start").to_edge(UP))
        for line in lines:
            words = line.split()
            if len(words) == 0:
                self.wait()
                self.clear()
                continue
            if  words[0] == "Can":
                continue
            if words[0] == "Tourne":
                if words[1] == "gauche":
                    turtle.rotate(int(words[3]))
                else:
                    turtle.rotate(-int(words[3]))
            elif words[0] == "Avance":
                start, end = turtle.advance(int(words[1]))
                self.add(Line(
                    start=start, end=end
                ))
            elif words[0] == "Recule":
                start,end = turtle.advance(-int(words[1]))
                self.add(Line(
                    start=start, end=end
                ))