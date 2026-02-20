from matplotlib import pyplot as plt
import json
import os
import numpy as np

class drawing(object):

    def __init__(self):
        #self.get_policy_compare_data()
        #self.draw_figure()
        self.get_policy_time()
        self.get_policy_score()
        self.draw_time_figure()
    
    
    def get_policy_compare_data(self):
        curr_dir = os.getcwd()
        filename = "p_compare.json"
        filepath = os.path.join(curr_dir, filename)
        with open(filepath, "r") as fr:
            self.p_compare_data = json.load(fr)
        fr.close()
    
    def draw_figure(self):
        scenarios = [f'Case {i}' for i in range(1, 9)]
        colors = ['#e41a1c', '#377eb8', '#4daf4a', '#ff7f00']  # vivid color palette

        plt.figure(figsize=(10, 6), facecolor="#f8f9fa")
        for idx, (policy, scores) in enumerate(self.p_compare_data.items()):
            plt.plot(scenarios, scores,
                    marker="o",
                    linestyle='-',
                    linewidth=2,
                    color=colors[idx],
                    label=policy,
                    markersize=7,
                    markerfacecolor='white',
                    markeredgewidth=2)

        plt.title("Policy satisfaction comparison in MED-NW",
                fontsize=24, fontweight='bold', color="#222222", pad=15)
        plt.xlabel("Case", fontsize=28, labelpad=10)
        plt.ylabel("Satisfaction score", fontsize=28, labelpad=10)
        plt.xticks(fontsize=12)
        plt.yticks(fontsize=12)
        plt.grid(axis="y", linestyle="--", alpha=0.6)
        plt.legend(title="Policy", fontsize=12, title_fontsize=13, loc='lower right')
        plt.tight_layout()

        plt.show()
    

    def get_policy_time(self):

        curr_dir = os.getcwd()
        filename = "bepte_time.json"
        filepath = os.path.join(curr_dir, filename)
        with open(filepath, "r") as fr:
            self.bepte_time = json.load(fr)
        fr.close()

    def get_policy_score(self):

        curr_dir = os.getcwd()
        filename = "sat_score.json"
        filepath = os.path.join(curr_dir, filename)
        with open(filepath, "r") as fr:
            self.p_sat_score = json.load(fr)
        fr.close()


    def draw_time_figure(self):
        num_attributes = [3, 4, 5, 6, 7]
        vivid_colors = ["#E53935", "#8E24AA", "#3949AB", "#43A047", "#FBC02D"]
        p_time = []
        for key in self.bepte_time:
            p_time.append(np.mean(self.bepte_time[key]) * 1000 )

        for key in self.p_sat_score:
            sat_score = self.p_sat_score[key]
        fig, ax1 = plt.subplots()
        color1 = "#E53935"
        ax1.set_xlabel('Number of Attributes', fontsize=28, labelpad=10)
        ax1.set_xticks(num_attributes)
        ax1.set_ylabel('Time (milliseconds)', color=color1, fontsize=28, labelpad=10)
        ax1.plot(num_attributes, p_time, marker='o', color=color1, label='Time')
        ax1.tick_params(axis='y', labelcolor=color1)
        ax1.set_ylim(0, 5)  # Set y-axis range for time

        ax2 = ax1.twinx()  # instantiate a second axes that shares the same x-axis

        color2 = "#43A047"
        ax2.set_ylabel('Satisfaction Score', color=color2, fontsize=28, labelpad=10)  # we already handled the x-label with ax1
        ax2.plot(num_attributes, sat_score, marker='s', color=color2, label='Score')
        ax2.tick_params(axis='y', labelcolor=color2)
        ax2.set_ylim(0, 1)  # Set y-axis range for time

        fig.tight_layout()  # otherwise the right y-label is slightly clipped
        plt.title('Time and Score vs Number of Attributes', fontsize=24, fontweight='bold', color="#222222", pad=15)
        plt.show()



def main():
    draw = drawing()

main()
